# Changelog

## [0.8.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.7.0...v0.8.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* version 1 policies are refused. The github: block becomes a list of providers (name, issuer, audience, jwks_uri, claims) with a top-level issuer (the broker's URL); issuer https://github.com means people's GitHub tokens. github.owner_id becomes the provider's claims.repository_owner_id, subject: users a profile for the https://github.com provider, match: is renamed claims: and takes one value or a list, and token.ttl/token.max_ttl move to the profile. See the broker README's migration table.
* POST /v1/actions/token, /v1/users/token and /v1/revoke are removed. Get credentials with an RFC 8693 token exchange at POST /oauth/token and revoke them at POST /oauth/revoke (RFC 7009); the action from this release does. Deploy the broker and upgrade the action together.
* a match pattern may only end in one * after a prefix, such as example-org/*. A bare *, a leading one or one in the middle is refused when the policy loads ("* is only allowed once, at the end, after a prefix").

### Features

* broker-issued tokens for other services, with discovery and JWKS ([#37](https://github.com/cf-contrib/cf-oidc-auth/issues/37)) ([d0bf8f7](https://github.com/cf-contrib/cf-oidc-auth/commit/d0bf8f76234917b7740708999ae703976fbcc992))
* OAuth endpoints: token exchange at /oauth/token, revocation at /oauth/revoke ([bad9004](https://github.com/cf-contrib/cf-oidc-auth/commit/bad90041ebcb06e1b52ce77fc2f1d4120249c6da))
* policy version 2, with identity providers ([#39](https://github.com/cf-contrib/cf-oidc-auth/issues/39)) ([dacaebc](https://github.com/cf-contrib/cf-oidc-auth/commit/dacaebc2e68067c07a69ad537e50f7ce75384831))
* profiles can be switched off with enabled: false ([#35](https://github.com/cf-contrib/cf-oidc-auth/issues/35)) ([dcdfc0f](https://github.com/cf-contrib/cf-oidc-auth/commit/dcdfc0f90388672b50acba110f07e3b8f9798e88))
* stricter match wildcards, and enabled: false on profiles ([#35](https://github.com/cf-contrib/cf-oidc-auth/issues/35)) ([dcdfc0f](https://github.com/cf-contrib/cf-oidc-auth/commit/dcdfc0f90388672b50acba110f07e3b8f9798e88))

## [0.7.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.6.0...v0.7.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* `subject: user`, released in 0.6.0, is now `subject: users`, so a profile's subject is also its route. A policy still using `user` fails to load with "subject: must be actions or users".

### Bug Fixes

* name the people subject users, like its route ([#31](https://github.com/cf-contrib/cf-oidc-auth/issues/31)) ([2323713](https://github.com/cf-contrib/cf-oidc-auth/commit/2323713bb47ef39b55344284f0d92ad63bb3317d))

## [0.6.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.5.0...v0.6.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* POST /v1/token is removed in favour of POST /v1/actions/token. Actions pinned at 0.5.0 or older get a 404 from this broker; upgrade the action with the broker.

### Features

* let people get credentials with their GitHub token ([#29](https://github.com/cf-contrib/cf-oidc-auth/issues/29)) ([55a552c](https://github.com/cf-contrib/cf-oidc-auth/commit/55a552ce64406e8f477c92b74769b48b438b025f)), closes [#28](https://github.com/cf-contrib/cf-oidc-auth/issues/28)

## [0.5.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.4.2...v0.5.0) (2026-09-30)


### Features

* grant R2 access with a buckets list, and ttl on the profile ([#25](https://github.com/cf-contrib/cf-oidc-auth/issues/25)) ([07ed1fd](https://github.com/cf-contrib/cf-oidc-auth/commit/07ed1fd87b284b9001ffe070b415037b62de2c16))
* prefix-scoped R2 temporary credentials in profiles ([#23](https://github.com/cf-contrib/cf-oidc-auth/issues/23)) ([3d293fa](https://github.com/cf-contrib/cf-oidc-auth/commit/3d293fa1eb91473ea30535937fe7c59595ca00c5)), closes [#22](https://github.com/cf-contrib/cf-oidc-auth/issues/22)
* several buckets per profile, exported as AWS profiles ([#27](https://github.com/cf-contrib/cf-oidc-auth/issues/27)) ([82ec113](https://github.com/cf-contrib/cf-oidc-auth/commit/82ec113a87abed3cfd8143cc10db735d1037e21a)), closes [#26](https://github.com/cf-contrib/cf-oidc-auth/issues/26)

## [0.4.2](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.4.1...v0.4.2) (2026-09-30)


### Bug Fixes

* **broker:** ship the policy as policy.json next to broker.js ([#17](https://github.com/cf-contrib/cf-oidc-auth/issues/17)) ([2ff0aed](https://github.com/cf-contrib/cf-oidc-auth/commit/2ff0aed255efe207a8742fe0d714990df98a8cc4))
* consistent names for the Secrets Store ID, bindings, token prefix and wrangler Worker ([#18](https://github.com/cf-contrib/cf-oidc-auth/issues/18)) ([c4b3f86](https://github.com/cf-contrib/cf-oidc-auth/commit/c4b3f86ee4cd8512b770e31369d3594aaa629b9c))
* name the Secrets Store ID secret_store_id and the wrangler Worker cf-oidc-broker ([c4b3f86](https://github.com/cf-contrib/cf-oidc-auth/commit/c4b3f86ee4cd8512b770e31369d3594aaa629b9c))
* rename the broker bindings to CF_OIDC_BROKER_* and the cf-auth: prefix to cf-oidc: ([c4b3f86](https://github.com/cf-contrib/cf-oidc-auth/commit/c4b3f86ee4cd8512b770e31369d3594aaa629b9c))
* **terraform:** name the resources broker and the URL output url ([#20](https://github.com/cf-contrib/cf-oidc-auth/issues/20)) ([1398229](https://github.com/cf-contrib/cf-oidc-auth/commit/1398229f578f91e8b02cf2a039349c1e063ff5b0))
* **terraform:** name the resources this ([#21](https://github.com/cf-contrib/cf-oidc-auth/issues/21)) ([9f2fafe](https://github.com/cf-contrib/cf-oidc-auth/commit/9f2fafec6128acf1d4547ff7467518945e16ffdc))

## [0.4.1](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.4.0...v0.4.1) (2026-09-30)


### Bug Fixes

* rename policy rules to profiles ([#15](https://github.com/cf-contrib/cf-oidc-auth/issues/15)) ([25bd573](https://github.com/cf-contrib/cf-oidc-auth/commit/25bd573e17b7bd68bc66458e73cd3bb4039d13b0))

## [0.4.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.3.0...v0.4.0) (2026-09-29)


### Features

* **terraform:** detect workers.dev from hostname ([#13](https://github.com/cf-contrib/cf-oidc-auth/issues/13)) ([56908b9](https://github.com/cf-contrib/cf-oidc-auth/commit/56908b9f114374d9c43920918e0a485b6a2e4538))

## [0.3.0](https://github.com/cf-contrib/cf-auth/compare/v0.2.0...v0.3.0) (2026-09-29)


### ⚠ BREAKING CHANGES

* **terraform:** the module moved from //examples/terraform to //packages/cf-auth-terraform, policy_file has no default, and release_tag defaults to the module's release instead of "latest".

### Features

* **terraform:** ship the Terraform module as packages/cf-auth-terraform ([#9](https://github.com/cf-contrib/cf-auth/issues/9)) ([10a3694](https://github.com/cf-contrib/cf-auth/commit/10a36941028c456ad0aef5426040d6de6a7d7118))

## [0.2.0](https://github.com/cf-contrib/cf-auth/compare/v0.1.0...v0.2.0) (2026-09-29)


### Features

* **action:** export S3-compatible R2 credentials with r2-credentials input ([#7](https://github.com/cf-contrib/cf-auth/issues/7)) ([98d8a43](https://github.com/cf-contrib/cf-auth/commit/98d8a43a2fc308384be5027e3dc3055862ebd1b5))

## 0.1.0 (2026-09-29)


### Features

* GitHub Actions OIDC broker and action for the Cloudflare API ([6109c27](https://github.com/cf-contrib/cf-auth/commit/6109c27a09ab32bf3d3f09425952c0464d97b779))


### Bug Fixes

* restore vitest 4 and start releases at 0.1.0 ([#5](https://github.com/cf-contrib/cf-auth/issues/5)) ([3515144](https://github.com/cf-contrib/cf-auth/commit/351514403aafca511e61bee3d8b552f1e68e7856))
