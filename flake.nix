{
  description = "cf-auth - GitHub Actions OIDC for the Cloudflare API.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "cf-auth";
          packages = [
            pkgs.nodejs_24
            pkgs.pnpm
            pkgs.wrangler
            pkgs.opentofu
          ];
        };
      }
    );
}
