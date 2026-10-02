//! Which profile a caller gets: their claims against the claim sets of their
//! provider and of each profile.

use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};

use super::{Claims, MIN_TTL, PolicyConfig, ProfileConfig, ProviderConfig, parse_duration};

/// Picks the profile to issue with, among those for `provider` and `audience`
/// only, or refuses with a `403` that says why. The token must match one of the
/// provider's claim sets, and one of the profile's.
pub fn select_profile<'a>(
    policy: &'a PolicyConfig,
    provider: &ProviderConfig,
    claims: &Claims,
    requested: Option<&str>,
    audience: &str,
) -> Result<&'a ProfileConfig, Error> {
    let forbidden = |message: String| Err(Error::new(ErrorCode::Forbidden, message));
    if !provider.takes(claims) {
        return forbidden(format!(
            "the token matches none of provider {}'s claim sets",
            provider.name
        ));
    }
    let mut profiles = policy
        .profiles
        .iter()
        .filter(|p| p.provider == provider.name && p.audience == audience);

    if let Some(requested) = requested {
        let profile = profiles.find(|p| p.name == requested);
        if let Some(profile) = profile
            && profile.enabled
            && profile.matches(claims)
        {
            return Ok(profile);
        }
        let named = policy.profiles.iter().find(|p| p.name == requested);
        return forbidden(match named {
            None => format!("unknown profile {requested}"),
            Some(named) if named.provider != provider.name => {
                format!("profile {requested} isn't for provider {}", provider.name)
            }
            Some(named) if named.audience != audience => {
                format!("profile {requested} isn't for {audience}")
            }
            Some(named) if !named.enabled => format!("profile {requested} is disabled"),
            Some(_) => format!("profile {requested} doesn't match the token"),
        });
    }

    let candidates: Vec<&ProfileConfig> = profiles
        .filter(|p| p.enabled && p.matches(claims))
        .collect();
    match candidates.as_slice() {
        [] => forbidden("no profile matches the token".into()),
        [profile] => Ok(profile),
        several => {
            let names: Vec<&str> = several.iter().map(|p| p.name.as_str()).collect();
            forbidden(format!(
                "profiles {} all match the token: name one",
                names.join(", ")
            ))
        }
    }
}

/// Resolves the requested TTL against the profile, in milliseconds. Requests
/// above `max_ttl` are clamped, not refused.
pub fn clamp_ttl(requested: Option<&str>, profile: &ProfileConfig) -> Result<u64, Error> {
    let Some(requested) = requested else {
        return Ok(profile.ttl);
    };
    match parse_duration(requested) {
        Some(ttl) if ttl >= MIN_TTL => Ok(ttl.min(profile.max_ttl)),
        _ => Err(Error::new(
            ErrorCode::BadRequest,
            format!("ttl {requested} isn't a duration of at least 1m"),
        )),
    }
}
