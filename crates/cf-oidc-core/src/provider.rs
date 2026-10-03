//! Verifying tokens: the [`Provider`]s whose tokens are accepted, and
//! [`Providers::verify`], which validates a token as RFC 7519 §7.2 and RFC
//! 8725 say, against the one its `iss` names.
//!
//! What verifying does with a provider is [`ProviderExt`]'s: implemented for
//! every [`Provider`], so an implementor can neither override it nor see it.

use std::ops::Deref;

use serde::Deserialize;
use worker::Date;

use crate::{
    Claims, Error, Header, Jwt, cache,
    cache::Lookup,
    error::invalid,
    fetch::{check_url, fetch_json},
    jwk::{JwkSet, RsaKey},
    jwt::{LEEWAY_SECS, Unverified},
    metadata,
};

/// An OpenID Provider whose tokens are accepted: the issuer, and what its
/// tokens must be to be verified. Implement it on your configuration's type.
///
/// It only says what's configured: verifying is [`Providers::verify`]'s.
pub trait Provider {
    /// Its issuer identifier, matched exactly against a token's `iss`.
    fn issuer(&self) -> &str;

    /// The audience a token's `aud` must contain: whoever verifies it. A
    /// trailing `/` is ignored, here and in the token.
    fn audience(&self) -> &str;

    /// Where its JWK Set is. `None`, the default, reads it from the
    /// `jwks_uri` in its metadata.
    fn jwks_uri(&self) -> Option<&str> {
        None
    }

    /// The `typ` its tokens must have (RFC 8725 §3.11), such as
    /// [`AT_JWT`](crate::AT_JWT), so another kind of token it issues can't
    /// pass for one. `None`, the default, takes any.
    fn typ(&self) -> Option<&str> {
        None
    }
}

/// The providers whose tokens are accepted. Written as a JSON array of
/// whatever `P` deserializes from.
///
/// Deserializing doesn't check it: [`check`](Self::check) does, saying where.
/// Nothing unchecked is ever fetched from, though: keys only come over HTTPS,
/// or plain HTTP on loopback.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Providers<P>(Vec<P>);

impl<P: Provider> Providers<P> {
    /// Verifies `token`, a JWT, against the provider its `iss` names: its
    /// header, its signature, then its registered claims. Returns that
    /// provider and the token, which [`verified`](crate::verified) gives back
    /// until it expires.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] when it isn't valid, and
    /// [`Error::TemporarilyUnavailable`] when its issuer's keys can't be had.
    pub async fn verify(&self, token: &str) -> Result<(&P, Jwt), Error> {
        let now_ms = Date::now().as_millis();
        if let Some(jwt) = cache::jwt(token, now_ms) {
            // Its signature holds; its header and claims are checked again,
            // as cheap as that is, against the provider it's from now.
            let provider = self.for_claims(&jwt.claims)?;
            provider.check_header(&jwt.header)?;
            provider.validate(&jwt.claims, now_ms)?;
            return Ok((provider, jwt));
        }

        let Unverified {
            jwt,
            signing_input,
            signature,
        } = Unverified::decode(token)?;
        let provider = self.for_claims(&jwt.claims)?;
        provider.check_header(&jwt.header)?;
        let key = provider.key(jwt.header.kid.as_deref(), now_ms).await?;
        if !key.verify(signing_input.as_bytes(), &signature).await? {
            return Err(invalid("bad signature"));
        }
        provider.validate(&jwt.claims, now_ms)?;

        if let Some(exp) = jwt.claims.exp() {
            let expires_at = (exp + LEEWAY_SECS) * 1000;
            cache::store_jwt(token, jwt.clone(), expires_at, now_ms);
        }
        Ok((provider, jwt))
    }

    /// The provider for `issuer`.
    pub fn find(&self, issuer: &str) -> Option<&P> {
        self.0.iter().find(|provider| provider.issuer() == issuer)
    }

    /// What deserializing can't check: that there's a provider, each one's
    /// issuer and `jwks_uri` are HTTPS (or loopback), its audience isn't
    /// empty, and no issuer is configured twice. `at` is where the providers
    /// are, for the message.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn check(&self, at: &str) -> Result<(), String> {
        if self.0.is_empty() {
            return Err(format!("{at} must name at least one provider"));
        }
        for (index, provider) in self.0.iter().enumerate() {
            let at = format!("{at}[{index}]");
            check_url(provider.issuer()).map_err(|why| format!("{at}.issuer {why}"))?;
            if let Some(jwks_uri) = provider.jwks_uri() {
                check_url(jwks_uri).map_err(|why| format!("{at}.jwks_uri {why}"))?;
            }
            if provider.audience().trim_end_matches('/').is_empty() {
                return Err(format!("{at}.audience must not be empty"));
            }
            if self.0[..index]
                .iter()
                .any(|other| other.issuer() == provider.issuer())
            {
                return Err(format!("{at}: {} is configured twice", provider.issuer()));
            }
        }
        Ok(())
    }

    /// The provider a token's claims say it comes from, by its `iss`, read
    /// unverified only to pick the keys to verify it with.
    fn for_claims(&self, claims: &Claims) -> Result<&P, Error> {
        let iss = claims.iss().unwrap_or_default();
        self.find(iss).ok_or_else(|| {
            let shown: String = iss.chars().take(200).collect();
            Error::InvalidToken(format!("no provider is for issuer {shown}"))
        })
    }
}

impl<P> Deref for Providers<P> {
    type Target = [P];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P> From<Vec<P>> for Providers<P> {
    fn from(providers: Vec<P>) -> Self {
        Self(providers)
    }
}

/// What verifying does with a provider. Implemented for every [`Provider`]
/// below, and private, so it can't be overridden to skip a check.
trait ProviderExt: Provider {
    /// What the provider needs of a token's JOSE Header beyond what decoding
    /// it checked: its `typ`, if the provider names one.
    fn check_header(&self, header: &Header) -> Result<(), Error> {
        match self.typ() {
            Some(typ) if !header.typ_is(typ) => Err(invalid(&format!("typ must be {typ}"))),
            _ => Ok(()),
        }
    }

    /// Validates a token's registered claims for this provider, at `now_ms`.
    fn validate(&self, claims: &Claims, now_ms: u64) -> Result<(), Error> {
        claims.validate(self.issuer(), self.audience(), now_ms / 1000)
    }

    /// The provider's key that `kid` names, or its only one when there's no
    /// `kid`: cached, or fetched from its `jwks_uri`.
    async fn key(&self, kid: Option<&str>, now_ms: u64) -> Result<RsaKey, Error> {
        let unknown = || invalid("unknown signing key");
        let issuer = self.issuer();
        match cache::key(issuer, kid, now_ms) {
            Lookup::Hit(key) => return Ok(key),
            Lookup::Unknown => return Err(unknown()),
            Lookup::Fetch => {}
        }

        let jwks_uri = match self.jwks_uri() {
            Some(jwks_uri) => jwks_uri.to_string(),
            None => metadata::jwks_uri(issuer).await?,
        };
        let jwks: JwkSet = fetch_json(&jwks_uri).await?;
        cache::store_keys(issuer, jwks.rs256_keys(), kid, now_ms).ok_or_else(unknown)
    }
}

impl<P: Provider + ?Sized> ProviderExt for P {}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;
    use crate::ALGORITHM;

    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://cf-oidc-exchange.example.com";

    #[derive(Debug, Deserialize)]
    struct TestProvider {
        issuer: String,
        #[serde(default = "audience")]
        audience: String,
        jwks_uri: Option<String>,
        typ: Option<String>,
    }

    fn audience() -> String {
        AUDIENCE.to_string()
    }

    impl Provider for TestProvider {
        fn issuer(&self) -> &str {
            &self.issuer
        }
        fn audience(&self) -> &str {
            &self.audience
        }
        fn jwks_uri(&self) -> Option<&str> {
            self.jwks_uri.as_deref()
        }
        fn typ(&self) -> Option<&str> {
            self.typ.as_deref()
        }
    }

    fn providers(value: Value) -> Providers<TestProvider> {
        serde_json::from_value(value).unwrap()
    }

    fn claims(iss: &str) -> Claims {
        let claims: Map<String, Value> = json!({ "iss": iss }).as_object().unwrap().clone();
        claims.into()
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let providers = providers(json!([{ "issuer": ISSUER }]));
        assert_eq!(
            providers.for_claims(&claims(ISSUER)).unwrap().issuer,
            ISSUER
        );
        assert_eq!(
            providers
                .for_claims(&claims("https://other.example.com"))
                .err(),
            Some(Error::InvalidToken(
                "no provider is for issuer https://other.example.com".into()
            ))
        );
        assert_eq!(providers.len(), 1, "it derefs to the providers");
    }

    #[test]
    fn checks_the_typ_a_provider_names() {
        let header = Header {
            alg: ALGORITHM.into(),
            kid: None,
            typ: Some("JWT".into()),
        };
        let typ = |typ: Value| providers(json!([{ "issuer": ISSUER, "typ": typ }]));
        assert_eq!(typ(Value::Null)[0].check_header(&header), Ok(()));
        assert_eq!(typ(json!("jwt"))[0].check_header(&header), Ok(()));
        assert_eq!(
            typ(json!("at+jwt"))[0].check_header(&header),
            Err(invalid("typ must be at+jwt"))
        );
    }

    #[test]
    fn check_says_whats_wrong_and_where() {
        let check = |value: Value| providers(value).check("providers");
        assert_eq!(check(json!([{ "issuer": ISSUER }])), Ok(()));
        assert_eq!(
            check(
                json!([{ "issuer": "http://localhost:8788", "jwks_uri": "http://127.0.0.1/jwks" }])
            ),
            Ok(())
        );
        for (value, expected) in [
            (json!([]), "providers must name at least one provider"),
            (
                json!([{ "issuer": "http://issuer.example.com" }]),
                "providers[0].issuer must be an https:// URL",
            ),
            (
                json!([{ "issuer": ISSUER, "jwks_uri": "http://issuer.example.com/jwks" }]),
                "providers[0].jwks_uri must be an https:// URL",
            ),
            (
                json!([{ "issuer": ISSUER, "audience": "/" }]),
                "providers[0].audience must not be empty",
            ),
            (
                json!([{ "issuer": ISSUER }, { "issuer": ISSUER }]),
                "providers[1]: https://token.actions.githubusercontent.com is configured twice",
            ),
        ] {
            assert_eq!(check(value.clone()), Err(expected.to_string()), "{value}");
        }
    }
}
