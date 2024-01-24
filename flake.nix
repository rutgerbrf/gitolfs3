{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2311.*.tar.gz";
    flake-utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.90.tar.gz";
    crane.url = "https://flakehub.com/f/ipetkov/crane/0.16.0.tar.gz";
    crane.inputs.nixpkgs.follows = "nixpkgs";
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, advisory-db, ... }@inputs:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ ];
          };

          craneLib = crane.lib.${system};
          src = craneLib.cleanCargoSource (craneLib.path ./.);

          commonArgs = {
            inherit src;
            strictDeps = true;
            pname = "gitolfs3";
            version = "0.1.0";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          gitolfs3 = craneLib.buildPackage (commonArgs // {
            # We already have the gitolfs3-nextest check
            doCheck = false;
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
          };

          formatter = pkgs.nixpkgs-fmt;
        });
}
