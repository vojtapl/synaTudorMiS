# libfprint
This folder will hopefully contain a patched version of libfprint, which should work with the devices mentioned.
NOTE: currently requires (this merge request)[https://gitlab.freedesktop.org/libfprint/fprintd/-/merge_requests/190/] on the fprintd side.

# Roadmap to libfprint merge request:
- fixing segfault on sending TLS data after opening device again
- adding alert stage to TLS
- Fix naming scheme
  - Naming of variables
- fix asserts
- What to do on full storage
- verifying endian independence
- writing test
- having the right clang-format settings
