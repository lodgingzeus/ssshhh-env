{
  description = "ssshhh-env: self-hosted SSH server for sharing .env files";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            delve
            go-tools # staticcheck
            govulncheck
            gosec
            sqlite # inspect the DB; check that no plaintext is stored
          ];

          # CGO stays available because `go test -race` needs it.
          # Release builds set CGO_ENABLED=0 (modernc.org/sqlite is pure Go).
          # Use the Nix-provided Go; never auto-download a toolchain.
          GOTOOLCHAIN = "local";
        };
      });
    };
}
