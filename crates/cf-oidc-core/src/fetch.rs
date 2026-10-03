//! Fetching an issuer's metadata and keys: only over HTTPS, or plain HTTP on
//! loopback, for a local issuer in development.

use serde::de::DeserializeOwned;
use worker::{AbortSignal, Fetch, Method, Request};

use crate::Error;

/// How long an issuer has to answer.
const FETCH_TIMEOUT_MS: u32 = 10 * 1000;

/// Whether `url` is somewhere keys may be fetched from: HTTPS, or plain HTTP
/// on a loopback address, for a local issuer in development. For checking
/// other URLs in a configuration the same way;
/// [`Providers::check`](crate::Providers::check) checks providers'.
///
/// # Errors
///
/// Why it isn't.
pub fn check_url(url: &str) -> Result<(), &'static str> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    let https = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    if url.contains(char::is_whitespace) || !(https || loopback) {
        return Err("must be an https:// URL");
    }
    Ok(())
}

/// The JSON at `url`. A URL [`check_url`] refuses is never fetched, whoever
/// configured it.
pub(crate) async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let unavailable =
        |err: worker::Error| Error::TemporarilyUnavailable(format!("fetching {url}: {err}"));
    check_url(url).map_err(|why| Error::TemporarilyUnavailable(format!("{url} {why}")))?;

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(url, Method::Get).map_err(unavailable)?;
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(FETCH_TIMEOUT_MS));
    let mut resp = Fetch::Request(req)
        .send_with_signal(&signal)
        .await
        .map_err(unavailable)?;
    if resp.status_code() != 200 {
        return Err(Error::TemporarilyUnavailable(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_http_only_on_loopback() {
        for url in [
            "https://issuer.example.com",
            "http://127.0.0.1:8788",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "http://issuer.example.com",
            "https://",
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
            "https://issuer.example.com/a b",
        ] {
            assert!(check_url(url).is_err(), "{url}");
        }
    }
}
