{
  description = "my libfprint dev setup";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, ... }@inputs: inputs.utils.lib.eachSystem [
    "x86_64-linux"
  ] (system: let
    pkgs = import nixpkgs {
      inherit system;
    };
  in {
    devShells.default = pkgs.mkShell rec {
      name = "libfprint dev setup";

      packages = with pkgs; [
        # native build inputs
        pkg-config
        meson
        ninja
        gtk-doc
        docbook-xsl-nons
        docbook_xml_dtd_43
        gobject-introspection

        # build inputs
        gusb
        pixman
        glib
        nss
        cairo
        libgudev

        # check inputs

        (python3.withPackages (p: with p; [ pygobject3 ]))

        # Development time dependencies
        gnutls
      ];
    };
  });
}
