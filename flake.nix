{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2311.*.tar.gz";
    flake-utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.88.tar.gz";
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ ];
          };

          gitolfs3 = pkgs.buildGoModule {
            name = "gitolfs3";
            src = ./.;
            vendorHash = "sha256-3JfeOHbqcgv4D3r/W4FwrXRs1raiQeOxifhO7qH5Wnc=";
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
