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

          gitolfs3 = craneLib.buildPackage {
            pname = "gitolfs3";
            version = "0.1.0";
            src = craneLib.cleanCargoSource (craneLib.path ./.);
          };
        in
        {
          packages.gitolfs3 = gitolfs3;
          packages.default = self.packages.${system}.gitolfs3;

          devShells.default = pkgs.mkShell {
            inputsFrom = [ gitolfs3 ];
          };

          formatter = pkgs.nixpkgs-fmt;
        });
}
