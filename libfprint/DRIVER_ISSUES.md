# synatlsmoc driver — issue checklist

**No compiler warnings** as of 2026-10-09 — the driver builds clean. Optional
leftover: `Db2Info db2_info;` (`synatlsmoc.c:2165`) is still uninitialised; it
does not warn today but is the same `read_ok &=` pattern as the two structs that
now use `= { 0 }`.

Local build/warning check, from the fork root:

```sh
nix-shell -p meson ninja pkg-config gcc glib.dev openssl.dev gusb pixman \
             cairo libgudev gobject-introspection python3
meson setup /tmp/synatlsmoc-build && ninja -C /tmp/synatlsmoc-build \
  libfprint/libfprint-2.so.2.0.0
```

## To-Do

- [ ] **PAIR-1: re-pair when the sensor rejects stored pairing data** (dual boot)
  - **Problem:** the sensor holds a single pairing; a new PAIR replaces the old
    one. When Windows' own pairing is rejected, it pairs again
    (`attemptUnpairAndPairSensor`, `synaWudfBioUsb111.dll @ 0x180009c48`, called
    from `CDeviceIdleSuspendResume @ 0x1800016e4` on
    `VCS_RESULT_SENSOR_NEED_TO_RESET_OWNER`). That silently invalidates the
    pairing Linux has stored. After a Windows boot, every open then fails in
    the TLS handshake. Relaunching doesn't help, because the same stored data
    is loaded again. Today the only way out is deleting fprintd's stored data
    by hand.
  - **Proposed fix:**
    - In `tls_session.c`, set a flag when the handshake is rejected: either an
      alert from the sensor during the handshake (typically 42
      bad_certificate) or our own handshake verification failing. Transport
      errors don't set it.
    - In `synatlsmoc_open_done`, if the flag is set, the pairing came from
      storage, and no repair was tried yet:
      1. clear `fpi-persistent-data`;
      2. drop the session;
      3. restart the open SSM. It goes through `OPEN_TLS_STATUS` (force close
         if needed) to `OPEN_SEND_PAIR`.
    - Once only; reset the guard after a successful open. If the retry fails
      too, report one clear error.
    - Windows also unpairs first. libfprint doesn't need to: PAIR without
      unpair works, as fprintd setups that re-pair on every start show.
  - **To check:**
    - Do enrolled prints still match after a re-pair? Templates live in the
      sensor DB, so they probably do.
    - Does fprintd save the new persistent data after a successful open?
  - **Test:** boot Windows, use the sensor, boot Linux, then verify an existing
    print. Quicker alternative: corrupt one byte of the stored host certificate
    or key, then open.
  - **Evidence:** `rev/FINDINGS.md`, 2026-10-16 (host-only
    `VCS_RESULT_SENSOR_*` codes, 0xcc).
