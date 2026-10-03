# cf-oidc-exchange-sdk

The Rust SDK for the broker's HTTP API, generated from
[`openapi/oidc/exchange/v1/exchangev1.yaml`](openapi/oidc/exchange/v1/exchangev1.yaml)
by `build.rs` with [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust).
Nothing generated is checked in: edit the spec. The health endpoints aren't
part of it: they're hand-written, in `src/service/handler.rs`, mounted into
`v1` beside the generated code.

| Feature | |
|---|---|
| (always) | the types: requests, responses, the authorization server metadata (RFC 8414), the JWKS, OAuth errors |
| `server` | `ExchangeServiceApi`, a response enum per operation, and `exchange_service_api_router`, an axum router that checks each request against the spec before it reaches a handler. `HealthHandler`, which answers the health endpoints beside it, `/health/live` and `/health/ready`. |
| `client` | `HttpClient`, a method per operation, and `HealthClient`, which asks the health endpoints. |

Bodies are form-encoded (`application/x-www-form-urlencoded`), as RFC 8693 and
RFC 7009 have it; anything else is a `415`.
