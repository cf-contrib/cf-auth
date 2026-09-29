# Changelog

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
