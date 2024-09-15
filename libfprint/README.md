# libfprint
This folder will hopefully contain a patched version of libfprint, which should work with the devices mentioned.
NOTE: currently requires (this merge request)[https://gitlab.freedesktop.org/libfprint/fprintd/-/merge_requests/190/] on the fprintd side.

# Roadmap to libfprint merge request:
- fixing pairing and loading / storing of pairing data in persistent storage
- adding alert stage to TLS
- Fix naming scheme
  - What to name the driver
  - Naming of variables
- Fix read_ok/written asserts
- fix asserts
- What to do on full storage
- unification of error messages
- verifying endian independence
- writing test
- having the right clang-format settings
