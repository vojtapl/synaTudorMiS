# libfprint

This folder contains a patched version of libfprint (now pushed to separate
repo, here submodule with possibly outdated commit link), which should work with
the devices mentioned. NOTE: currently requires
[a modified merge request](https://gitlab.freedesktop.org/libfprint/fprintd/-/merge_requests/190/)
on the fprintd side, which can be found
[here](./fprintd-load-store-persistent-data-from-device.patch)

Note: old non-async driver variant now stored only for reference in
syna_tudor_moc.

# Roadmap to libfprint merge request:

- remove fixmes and todos
- adding alert stage to TLS
- Fix naming scheme
  - Naming of variables
  - figure out the naming of TLS things
- fix asserts
- What to do on full storage
- verifying endian independence
- writing test
- having the right clang-format settings
