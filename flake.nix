{
  description = "Wireguard alternative using Iroh";

  outputs = { self, nixpkgs, systems, ... }@inputs: let
    pkgs' = system: import nixpkgs {
      inherit system;
      overlays = [ inputs.rust-overlay.overlays.default ];
    };
    forSystems = f: nixpkgs.lib.genAttrs (import systems) (system: let
      pkgs = pkgs' system;

      mkDevShell = args: pkgs.mkShell (let
        options = let
          first = args options;
        in {
          shellHook = ''
            export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
            export NIX_CFLAGS_LINK="$NIX_CFLAGS_LINK -fuse-ld=mold"
          '';
          buildInputs = [ pkgs.nodejs ];
          nativeBuildInputs = first.nativeBuildInputs ++ [
            pkgs.mold
            pkgs.rust-analyzer
            pkgs.cargo-edit
            pkgs.cargo-deb
          ];
        } // (builtins.removeAttrs first [ "nativeBuildInputs" ]);
      in options);

      args = { inherit pkgs mkDevShell; };
    in f args);

    cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    msrv = cargoToml.workspace.package.rust-version;
  in {
    devShells = forSystems ({ pkgs, mkDevShell, ... }: let
      mkShell = toolchain: mkDevShell (self: {
        nativeBuildInputs = [
          (toolchain.override {
            targets =  [ "x86_64-unknown-linux-musl" ];
          })
          pkgs.libressl
          pkgs.pkg-config
        ];
      });
      msrvShadow = msrv;
    in rec {
      default = stable;

      stable = mkShell pkgs.rust-bin.stable.latest.default;
      nightly = mkShell (pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default));
      msrv = mkShell pkgs.rust-bin.stable.${msrvShadow}.default;
    });
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
}

