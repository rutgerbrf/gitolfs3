{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2311.*.tar.gz";
    flake-utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.88.tar.gz";
    crane.url = "https://flakehub.com/f/ipetkov/crane/0.15.1.tar.gz";
    crane.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, crane, nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ ];
          };

          craneLib = crane.lib.${system};

          gitolfs3 = pkgs.buildGoModule {
            name = "gitolfs3";
            src = ./.;
            vendorHash = "sha256-3JfeOHbqcgv4D3r/W4FwrXRs1raiQeOxifhO7qH5Wnc=";
          };
        in
        {
          packages.gitolfs3 = gitolfs3;
          packages.gitolfs3-rs = craneLib.buildPackage {
            src = craneLib.cleanCargoSource (craneLib.path ./rs);
          };
          packages.default = self.packages.${system}.gitolfs3;

          devShells.default = pkgs.mkShell {
            inputsFrom = [ gitolfs3 ];
          };

          formatter = pkgs.nixpkgs-fmt;
        });
}
