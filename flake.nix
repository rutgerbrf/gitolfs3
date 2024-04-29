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
          src = craneLib.cleanCargoSource (craneLib.path ./.);

          commonArgs = {
            inherit src;
            strictDeps = true;
            pname = "gitolfs3";
            version = "0.1.0";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          gitolfs3-bare = craneLib.buildPackage (commonArgs // {
            # We already have the gitolfs3-nextest check
            doCheck = false;
          });

          gitolfs3-man = pkgs.stdenv.mkDerivation {
            name = "gitolfs3-man";

            src = ./docs/man;

            installPhase = ''
              install -D gitolfs3-authenticate.1 $out/share/man/gitolfs3-authenticate.1
              install -D gitolfs3-server.1 $out/share/man/gitolfs3-server.1
              install -D gitolfs3-shell.1 $out/share/man/gitolfs3-shell.1
            '';
          };

          gitolfs3 = pkgs.buildEnv {
            name = "gitolfs3";

            paths = [ gitolfs3-bare gitolfs3-man ];

            pathsToLink = [ "/bin" "/share/man" ];
          };
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
