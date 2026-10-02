{
  description = "cf-oidc-auth - exchange an OIDC identity for short-lived Cloudflare credentials.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "cf-oidc-auth";
          packages = [
            # The TypeScript broker and the action, until the Rust Worker replaces the broker.
            pkgs.nodejs_24
            pkgs.pnpm
            # The Rust Worker.
            pkgs.pkg-config
            pkgs.worker-build
            rust-toolchain
            # Both.
            pkgs.wrangler
            pkgs.opentofu
          ];
        };
      }
    );
}
