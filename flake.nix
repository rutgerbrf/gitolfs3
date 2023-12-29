{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2311.*.tar.gz";
    flake-utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.88.tar.gz";
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    {
      nixosModules = rec {
        gitolfs3 = import ./module self;
        default = gitolfs3;
      };
    } // flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ ];
          };

          gitolfs3 = pkgs.buildGoModule {
            name = "gitolfs3";
            src = ./.;
            vendorHash = null;
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
