let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  name = "tudor-dev-env";

  buildInputs =  with pkgs; [
    python3
    python3Packages.cryptography
    python3Packages.pyusb
    python3Packages.pip
  ];

  shellHook = ''
    # Tells pip to put packages into $PIP_PREFIX instead of the usual locations.
    # See https://pip.pypa.io/en/stable/user_guide/#environment-variables.
    export PIP_PREFIX=$(pwd)/_build/pip_packages
    export PYTHONPATH="$PIP_PREFIX/${pkgs.python3.sitePackages}:$PYTHONPATH"
    export PATH="$PIP_PREFIX/bin:$PATH"
    unset SOURCE_DATE_EPOCH

    pip install .
  '';
}

