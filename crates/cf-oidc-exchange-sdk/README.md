# cf-oidc-exchange-sdk

The Rust SDK for the broker's HTTP API, generated from
[`openapi/oidc/exchange/v1/exchangev1.yaml`](openapi/oidc/exchange/v1/exchangev1.yaml)
by `build.rs` with [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust).
Nothing generated is checked in: edit the spec.

| Feature | |
|---|---|
| (always) | the types: requests, responses, the discovery document, the JWKS, errors |
| `server` | `ExchangeServiceApi`, a response enum per operation, and `exchange_service_api_router`, an axum router that checks each request against the spec before it reaches a handler |
| `client` | `HttpClient`, a method per operation |

Bodies are form-encoded (`application/x-www-form-urlencoded`), as RFC 8693 and
RFC 7009 have it; anything else is a `415`.
