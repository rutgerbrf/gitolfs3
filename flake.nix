{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2311.*.tar.gz";
    flake-utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.92.tar.gz";

    crane = {
      url = "https://flakehub.com/f/ipetkov/crane/0.16.3.tar.gz";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay, advisory-db, ... }@inputs:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          src =
            let docsFilter = path: _type: builtins.match ".*docs/man/.*\.[1-9]$" path != null;
                docsOrCargo = path: type:
                  (docsFilter path type) || (craneLib.filterCargoSources path type);
            in pkgs.lib.cleanSourceWith {
              src = craneLib.path ./.;
              filter = docsOrCargo;
            };

          commonArgs = {
            inherit src;
            strictDeps = true;
            pname = "gitolfs3";
            version = "0.1.0";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          gitolfs3 = (craneLib.buildPackage (commonArgs // {
            # We already have the gitolfs3-nextest check
            doCheck = false;
          })).overrideAttrs(old: old // {
            nativeBuildInputs = (old.nativeBuildInputs or []) ++ [
              pkgs.installShellFiles
            ];

            postInstall = (old.postInstall or "") + ''
              installManPage docs/man/gitolfs3-authenticate.1
              installManPage docs/man/gitolfs3-server.1
              installManPage docs/man/gitolfs3-shell.1
            '';

            outputs = [ "out" ];
          });
        in
        {
          checks = {
            inherit gitolfs3;

            gitolfs3-clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            });

            gitolfs3-doc = craneLib.cargoDoc (commonArgs // {
              inherit cargoArtifacts;
            });

            # Check formatting
            gitolfs3-fmt = craneLib.cargoFmt commonArgs;

            # Audit dependencies
            gitolfs3-audit = craneLib.cargoAudit (commonArgs // {
              inherit advisory-db;
            });

            # Run tests with cargo-nextest
            gitolfs3-nextest = craneLib.cargoNextest (commonArgs // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
            });
          };

          packages.gitolfs3 = gitolfs3;
          packages.default = self.packages.${system}.gitolfs3;

          devShells.default = craneLib.devShell {
            checks = self.checks.${system};

            packages = [ rustToolchain pkgs.rust-analyzer ];
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          };

          formatter = pkgs.nixpkgs-fmt;
        });
}
