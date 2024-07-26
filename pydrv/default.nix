let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  name = "tudor-dev-env";

  buildInputs = with pkgs; [
    python3
    python3Packages.cryptography
    python3Packages.matplotlib
    python3Packages.pyusb

    libusb
  ];

  venvDir = "venv37";

  postshellHook = ''
    sudo pip install .
    sudo python -m tudor.driver usb
  '';
}
