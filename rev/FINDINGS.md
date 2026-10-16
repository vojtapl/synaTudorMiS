# Findings

Running log of reverse-engineering findings made with the help of an AI agent
through Ghidra (ReVa). For the high-level protocol see `proto.txt`; for raw
low-level notes see `rev.txt`.

Each entry:

- **Where**: program and address, e.g. `synaWudfBioUsb111.dll @ 0x180012340`
  (addresses differ between driver versions)
- **What**: the finding
- **Evidence**: decompilation, xrefs, constants or captures supporting it
- **Status**: `unverified` (AI work, Ghidra names still prefixed `ai_`) →
  `verified` (checked by the user) → `in driver` (used in `libfprint/`)
- **Ghidra changes**: renames, types and comments made, all marked as
  described in `/CLAUDE.md`

## Open questions

- Provisioning:
  - v111 never sends PROVISION.
  - v136 does, on every init, as "IPT provisioning": BOOTLDR_PATCH (0x7d) with
    a built-in 48 KB blob, then PROVISION `0e 97 00 00 00`. It runs only if
    GET_VERSION `interface` bit 3 is clear. See the v136 entry.
  - Open:
    - does it move the provision state to 3?
    - what do the payload bits 0x97 / 0x17 mean?
    - what does `interface` read on our sensors (00C9/00D1/00E7/00FF)?
    - does any v111-line sensor have `interface & 0x08 == 0`?
    - what does "IPT" stand for?
- Does a PAIR (0x93) from Linux invalidate templates enrolled under Windows'
  pairing? The README says enrollments are tied to pairing data.
- Command IDs for the 21 `VCSFW_*` names that appear only in non-v111 builds
  (`rev/notes/dll-survey/vcsfw_names.json`). They can be read from the
  ID-to-name table in v136.
- Capture flow (the remaining steps after FRAME_ACQ)
- FRAME_ACQ: meaning of the block header bytes (`01 00 00 08` / `01 00 00 0c`),
  of the mode-3 block payload (`14 00 02 00`), and of acq flag bits 0x1000 / 0x10

## Log

<!-- newest first -->

### 2026-10-16: 0xA6 is VCSFW_CMD_MSBM_CONNECT; TIDLE_SET is never sent on USB; host-only VCS_RESULT_SENSOR_* codes

- **Where**: `synaWudfBioUsb111.dll`, `synaWudfBioUsb123.dll`, `synaWudfBioUsb136.dll`
  (6.0.69.1136, msucat); objdump only for v110 and v139. Addresses below.
- **What**:
  - **0xA6 = `VCSFW_CMD_MSBM_CONNECT`, the sensor side of Windows Hello
    SDCP secure connect.**
    - **Name:** v111 and v123 don't name it; their loggers go from 0xa5 to
      0xac/0xab. v136 has the string "Send VCSFW_CMD_MSBM_CONNECT failed with
      result = %d" (`@ 0x18020b900`), used in `_tudorSecureBioSendMSBMCmd`
      (`@ 0x1800b7220`), which builds `(0xa6, 0xb1)`. The survey finds the name
      in builds 105, 136, 164, 167 and 171.
    - **Only sender:** IOCTL `0x44002c` (secure connect) →
      `CBiometricDevice::OnConnectSecure` → `vfmSecureBioConnect` →
      `tudorIoctl` 0x1d → `smtWithPairing` (v111 `@ 0x18008ea10`, v123
      `FUN_180087b50`) → `tudorSecureBioConnect(h, 0xa6, ...)`. Never part of
      init, enroll or match. This confirms item 7 of the 2026-10-11 entry.
    - **Command (177 bytes):** `a6`, a 32-byte host nonce, a u32 key length
      (0 or 0x41), then the key (probably an uncompressed P-256 host key).
      With a key, the driver first enters an "SBL" mode via 0xaa
      (`reset_sensor_2`) with a USB reset, and leaves it afterwards
      (`reset_sensor`). v111 and v123 skip the exit when the command fails;
      v136 fixes this.
    - **Reply (up to 2234 bytes):** what looks like the SDCP ConnectResponse:
      32-byte values, model certificate, two 65-byte keys, a 32-byte hash,
      two 64-byte signatures. Windows appends two built-in CA certificates
      and returns it as `WINBIO_SECURE_CONNECTION_DATA`. The SDCP field
      mapping is inferred from the field sizes.
  - **`VCSFW_CMD_TIDLE_SET` (0x57) is never sent on USB.**
    - **Sender:** `setIDLETimeout` (v111 `@ 0x180082dc0`, v123
      `FUN_180080440`) sends `57 c4 09` (200 ms in 80 µs units) and expects a
      2-byte reply.
    - **Callers:** only two, both at init. The first-init one is v111
      `@ 0x180077902`, v123 `_tudorSensorInit @ 0x180075813`. The re-init one
      is v111 `_tudorInitDevice @ 0x180078160`, v123 `@ 0x180075f21`.
    - **Gate:** both skip the call when byte 5 of DEVICE_INFO (IOCTL 0x65,
      kept at `hSensor+0x19`) equals 1. The USB protocol layer hard-codes
      that byte to 1 (v111 `@ 0x180080dc8`, v123 `@ 0x18007e728`).
    - **Other builds:** v110 and v139 are the same. v136 sends only when the
      byte is 2 or 3; USB still writes 1.
    - **Interpretation (inferred):** the byte is a transport type, 1 = USB.
      `rev.txt` called it "always zero" and has been corrected. The user's
      name `smt2_or_3` for `hSensor+0x19` probably comes from a type shared
      with a VFM-level object that `vfmCaptureStart` writes.
  - **`VCS_RESULT_SENSOR_*` codes that libfprint lacks are all host-side.**
    - The v111 and v123 name tables (`@ 0x18019c528` / `@ 0x18017c738`) are
      identical. No firmware status word maps to any of the missing codes in
      either converter (v111 `@ 0x180087f20`, v123 `@ 0x180085550`).
    - **0xcc `NEED_TO_RESET_OWNER`:**
      - **Produced by** `tudorTlsSessionStart` (v111 `@ 0x180088150`) when:
        - there is no host partition or pairing tag, or `tudorTlsInitCtx`
          fails;
        - any handshake fails, other than with MALFUNCTIONED
          (`@ 0x18008899b`);
        - the sensor sends TLS alert 42 bad_certificate
          (`ssiTlsReceiveData @ 0x18009652b`).
      - **Handled by** `InitializeDevice` (`@ 0x180004eb1`): it re-inits with
        the registry pairing data, else reports "unpaired".
    - **0xcb `UNAVAILABLE`:**
      - **Produced by** `_tudorInitDevice` (`@ 0x180077f25`) after more than
        4 init attempts. v123 also uses it when the USB device is gone
        (0xc000000e).
      - **Handled by** `InitializeDevice` (`@ 0x180004ea6`): it calls
        `vfmDeviceHardReset` and fails with WINBIO_E_DEVICE_FAILURE.
    - **0xda `FRAME_NOT_READY`** (status 0x5b6) is a soft reject in
      `CaptureImage` ("too fast", retry), not an error.
    - **Others:** 0xd5 and 0xd2 are Windows-only (host partition full,
      driver open). 0xc9, 0xcd–0xd0, 0xd4 and 0xd6–0xd9 are never produced.
    - **Converter differences:** v123's converter has no entries for 0x403,
      0x680, 0x683, 0x6ea or 0x315; these become 0xca. It adds
      0x50b → 0x137, which has no name. `ssiTlsReceiveData` can also return
      0xd3, not only MALFUNCTIONED as the 2026-10-11 entry says.
- **Evidence**: decompilation and disassembly at the addresses above, found
  by three read-only agent investigations. The name tables were parsed
  directly from the DLL files.
- **Status**: unverified. Nothing was tested on hardware.
- **Implications for `libfprint`** (not applied):
  - add `VCSFW_CMD_MSBM_CONNECT = 0xa6`, name only;
  - don't send TIDLE_SET or MSBM_CONNECT;
  - consider a clear "re-pair" error for the 0xcc cases;
  - consider a retry for status 0x5b6 during capture.
- **User annotation that looks wrong**: the v111 `VCS_RESULT` enum names 0xcb
  `VCS_RESULT_SENSOR_IN_AUTONOMOUS_MODE` (visible at `InitializeDevice
  @ 0x180004ea6`). The DLL's own table says 0xcb is `SENSOR_UNAVAILABLE` and
  0xcd is `SENSOR_IN_AUTONOMOUS_MODE`. Left unchanged.
- **Ghidra changes**: none.

### 2026-10-16: When v123 sends each LED_EX2 event; enroll events 2/3 were swapped

- **Where**: `synaWudfBioUsb123.dll` (Kensington v6.0.25.1123, INF
  `synaWudfBioUsbUwpOne.inf`, which lists only `047D:8054` and `06CB:00D6`):
  - `@ 0x180056180` `vfmUtilSetLedEvent`, `@ 0x180056740` `_vfmUtilSetLedEvent`
  - `@ 0x180056650` `_vfmUtilLedHandler`, `@ 0x1800564c0` `_vfmLedHandlerProc`
  - `@ 0x180053d60` (`vfmUtilCaptureImage`), `@ 0x18005b2f0` (capture loop),
    `@ 0x18005ba50` (wait for capture callback)
  - `@ 0x18004fbc0` (`vfmUtilEnrollAddImage`), `@ 0x1800977f0` (`misEnrollAddImage`)
  - `@ 0x180050d80` (`vfmUtilAuthImageToTemplates`), `@ 0x180006ca0` (`CBiometricDevice::OnD0Exit`)
- **What**:
  - **Every LED failure is only logged.** All seven callers log "Failed to set
    led event" and go on. None fails the operation.
  - **Event 0 (idle):** at finger detection during capture
    (`SSI_CAPTURE_STATUS_FD_DETECTED`), when the capture wait fails or is
    cancelled, and at `OnD0Exit`. Not after enroll finish, and not after a
    match result.
  - **Event 1 (waiting):** in `vfmUtilCaptureImage` just before
    `vfmCaptureStart` (FRAME_ACQ).
  - **Enroll:** `misEnrollAddImage` sets status word 3 to 1 for a rejected
    sample and returns 0x131. A completed enrollment returns 0 with status 2.
    `vfmUtilEnrollAddImage` then sends:
    - event **2** for an accepted sample and for the completed enrollment,
    - event **3** for a rejected sample or any add-image error.
    So event 2 = accepted, event 3 = rejected. `rev/notes/led-ex2-default-profiles.md`
    had them the other way round. This fits the colours: events 2 and 4 use the
    `0x5xx` values of the waiting/success profiles, events 3 and 5 the `0x1xx`
    values of the failure profile.
  - **Match:** event 4 when the sensor match succeeds, event 5 when it fails.
    This is the sensor result; the WinBio identity check comes later. No LED
    when `(flags & 1)` is set.
  - **A timed indication is never cut short.** `_vfmUtilSetLedEvent` keeps the
    last event, its start time and duration. If the last event isn't 1 and
    hasn't run out, the new event is dropped: the old one is re-sent with the
    remaining time, and the handler thread is woken. After that time,
    `_vfmLedHandlerProc` sends event 1 if a capture is running (state 4).
  - **Registry switch:** `session+0x420 != 0` ("Led disabled in registry")
    skips all LED commands.
  - **Serialization** (`sendLedEx2Cmd @ 0x180082960`, checked in the
    disassembly). Per 20-byte action it copies bytes +0..1, +4..7, +8..9,
    +12..13 and +16..17; everything else is sent as zero. The earlier note said
    +4..15 were copied whole and +16 ignored. For the built-in table both read
    the same. A byte-for-byte simulation from the raw table at `0x1800cc8a0`
    gives exactly the six commands synatlsmoc builds.
  - **Reply** is 2 bytes (`pOutInfoBlob.cbSize = 2`), the same as FRAME_FINISH
    (0x81). Retried once on `0xd1`, which the status converter
    (`@ 0x180085550`) produces only for status `0x401`.
- **Evidence**: decompilation of the functions above. `vfmUtilSetLedEvent` has
  exactly seven callers.
- **Status**: in driver (branch `synatlsmoc-led-ex2`, uncommitted). The driver
  sends event 1 after FRAME_ACQ, not before, so that the wait for a running
  blink doesn't delay the capture. It sends idle after FRAME_READY, since it
  doesn't arm FINGER_DOWN during capture.
- **Ghidra changes**: none.

### 2026-10-14: Only MATCH_FAILED counts as "no match"; 0x0683 after identify is an error

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x18009ee80` `misIdentifyMatchCmd`
  - `@ 0x18009cb90` `misAuthImageToTemplates`
  - `@ 0x18004ec10` `_vfmMatchImageToTemplates`
  - `@ 0x1800562c0` `_vfmUtilMisMatchImageToTemplates`
  - `@ 0x18004d7e0` `_vfmMatchPostProcess`
- **What**:
  - **No special case below the vfm layer.** `misIdentifyMatchCmd` sends IDENTIFY (0x99) and returns the converted status. `misAuthImageToTemplates` and `_vfmMatchImageToTemplates` log "authImageToTemplates failed" for any non-zero result and return it unchanged.
  - **Only MATCH_FAILED is a no-match.** `_vfmUtilMisMatchImageToTemplates` treats `VCS_RESULT_MATCHER_MATCH_FAILED` (status 0x509) as an ordinary no-match and still fetches the match results. Every other result is a failure ("vfmMatchImageToTemplates failed") and returns early. That includes `VCS_RESULT_GEN_OBJECT_DOESNT_EXIST` (status 0x683 → 0x76).
  - **Request layout with TUIDs.** `[1..4]=1`, `[5..8]=numTuids*16`, `[9..12]=0`, then the TUIDs. The secureBio nonce (`tudorGetParameterBlob(8)`) goes in only when no TUIDs are passed (`[9..12]` = nonce size). This matches what libfprint sends.
  - **Windows does more around identify than libfprint does.**
    - before the match: `misAuthStart`, an image-quality gate (`vfmUtilAuthImageQuality`), `_vfmGetEnrollments` and a template cache (`palSecureCtxCache`, `chachedCnt`);
    - after a match: `_vfmMatchPostProcess` runs a template update when `authUpdateTemplateCnt != 0` (`misAuthUpdateTemplates` + `templateSerialize`).
    - Whether any of this sends sensor commands that libfprint lacks hasn't been checked.
- **Hardware (2026-10-13/14), 3 runs**: the result depends on whether the request lists TUIDs.

  | Request | Result when the finger doesn't match |
  | --- | --- |
  | without TUIDs (`99 01000000 00000000 00000000`) | 0x0509 every time (4/4) |
  | with one TUID | 0x0683 every time (5/5) |

  - Matches used the same TUID request, byte for byte.
  - In the last run, IDENTIFY took 83 ms for a match and 53 ms for 0x0683, so the matcher did run.
  - Ruled out: a frame that wasn't ready. The interrupt packet before FRAME_FINISH was `02 00 00 00 00 01 xx` for both the match and the 0x0683 run, and byte 1 was always 0.
  - Conclusion: 0x0683 means "no match among the listed templates", and 0x0509 means "no match in the whole database".
  - libfprint reports both as no-match, which is the right result for a user. The vfm-level "error" in Windows is an internal distinction.
  - Open: Windows' cached device state (`VCSDRV_IOCTL_GET_DEVICE_STATE`) apparently isn't the raw interrupt packet, because byte 1 never changes on Linux.
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-13: Windows always finishes a started capture, also on cancel

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x180057110` `vfmUtilCaptureImage`
  - `@ 0x180057ca0` `vfmUtilStopCapture`
  - `@ 0x1800508a0` `vfmCaptureFinish`
  - `@ 0x18007b0d0` `tudorCaptureFinish`
  - `@ 0x18007a3a0` `tudorCaptureStart`
  - `@ 0x180083650` `tudorCmdFrameFinish`
  - `@ 0x1800832c0` `sendCmdFrameAcq`
- **What**:
  - **Cancel.** `vfmUtilStopCapture` only sets `captureCancelled` and signals the capture event. The capture loop then exits with VCS_RESULT_GEN_OPERATION_CANCELED.
  - **Finish runs on every outcome.**
    - Once `vfmCaptureStart` has succeeded, `vfmUtilCaptureImage` always reaches `captureFinish:` and calls `vfmCaptureFinish(hVfm, isCanceled)`. That covers success, error and cancel.
    - On cancel the result stays CANCELED even if finishing fails.
  - **What finish sends.**
    - `tudorCaptureStart` sets `pCaptureCtx->forcefull = 1` only after FRAME_ACQ succeeds (the field name is the user's).
    - `tudorCaptureFinish` does `setEvents(0)` + `tudorCmdFrameFinish` (VCSFW 0x81) only when `forcefull == 1`. It then clears the capture context.
    - With `isCancelled` set, `vfmCaptureFinish` also calls `FUN_18004fd10`, which only frees host-side buffers.
  - **No special case for 0x05cb.** `sendCmdFrameAcq` retries only on VCS_RESULT 0xdf (status 0x6ea, 100 ms apart). Status 0x05cb (VCS_RESULT 0xdd) gets no special handling.
- **For libfprint**:
  - A cancelled verify/enroll left the capture armed. The next FRAME_ACQ then failed with status 0x05cb, which is probably "capture already in progress" (hardware log, 2026-10-13).
  - The unconditional USB reset in open used to hide this.
  - Fix: after FRAME_ACQ has succeeded, any failure must still send EVENT_CONFIG(none) + FRAME_FINISH.
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-11: Windows resets the device at (re)init and drops the session on errors without an alert

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x180077db0` `_tudorInitDevice`
  - `@ 0x180088150` `tudorTlsSessionStart`
  - `@ 0x180088c60` `tudorTlsSessionClose`
  - `@ 0x1800866d0` `tudorSecureBioConnect`
- **What**:
  - **Reset at init.** `_tudorInitDevice` sends protocol IOCTL 0x68 (USB
    reset, `palWinUsbReset`) when `hSensor->someTickCnt == 0`, before
    GET_VERSION and `tudorTlsSessionStart`. This happens once per
    initialization, not per request (see the "one TLS session" entry).
  - **Recovery from failure.**
    - Any init failure sets `someTickCnt = 0`, increments `initAttemptCnt`, and
      asks for a retry after 100 ms. At most 5 attempts are made.
    - So the retry starts with a reset.
    - "Sensor in secure session but host isn't" also sets `someTickCnt = 0`
      and fails with SENSOR_MALFUNCTIONED. **Windows relies on the USB reset
      to clear a sensor-side session left over from someone else.**
  - **`tudorTlsSessionClose(h, sendAlert)`.**
    - Only when `sendAlert == 1` and the sensor reports a session does it send
      close_notify (`ssiTlsAlertNotify`). In every case it then frees the
      context (`ssiTlsUninit`).
    - Error paths pass 0, i.e. drop the host state without an alert:
      - `tudorSecureBioConnect` on a decrypt failure (SENSOR_MALFUNCTIONED);
      - `tudorTlsSessionStart` on handshake failure;
      - `tudorTlsSuspendSession`;
      - `tudorSecurityDoUnPair`.
    - Only `smtWithPairing` and `tudorSensorUpdate` (firmware update) pass 1.
- **For libfprint (PERF-1)**:
  - reset only when the host has no session, i.e. at (re)init;
  - after a transport or decrypt failure, drop the host session without sending
    anything, and let the next open re-init (reset + handshake).
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-11: Windows keeps one TLS session for the driver's lifetime

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x1800016e4` `CDeviceIdleSuspendResume`
  - `@ 0x180004bdc` `CBiometricDevice::InitializeDevice`
  - `@ 0x180006a80` / `@ 0x180006950` `OnD0Exit` / `OnD0Entry`
  - `@ 0x180088150` `tudorTlsSessionStart`
  - `@ 0x180088eb0` `tudorTlsSensorSessionStatusGet`
  - `@ 0x180088c60` `tudorTlsSessionClose`
- **What**:
  - **Every WBF request** (capture, enroll, delete, …) is wrapped in
    `CDeviceIdleSuspendResume`, which calls `InitializeDevice`.
    `InitializeDevice` runs `vfmDeviceInitialize` → `tudorInitDevice` (which
    includes `tudorTlsSessionStart`) only while the "initialized" byte
    (`this+0x89`) is 0. It sets the byte to 1 on success, and only
    `ProcessPairing` clears it. So the device is initialized, and the handshake
    done, once.
  - **D0 transitions keep the session.** `OnD0Exit` stops the capture threads and
    `OnD0Entry` resumes them. Neither closes TLS.
  - **`tudorTlsSessionStart` returns at once** when both the host and the sensor
    report a session. The sensor side comes from
    `VCSDRV_IOCTL_GET_TLS_STATE` (0x66). If only the host has a session, it
    reuses the context (see the resumption entry). If only the sensor has one,
    it returns `SENSOR_MALFUNCTIONED`.
  - **The session is closed only** on module uninit or open (`session_close`), on
    error paths (`tudorSecureBioConnect` on a decrypt failure → `SessionClose(0)`,
    no alert), on unpair, and on firmware update.
- **For libfprint**: the open SSM already has the same 4-way check
  (`OPEN_HANDLE_TLS_STATUSES`, via the vendor control request
  `REQUEST_TLS_SESSION_STATUS`). Close, however, always sends close_notify
  and frees the session.
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-11: TLS session resumption in Windows

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x180094430` `ssiTlsHandshakeClientHello`
  - `@ 0x180096fe0` `randleServerHello` (the user's name)
  - `@ 0x180088150` `tudorTlsSessionStart`
  - `@ 0x180089260` `tudorTlsSuspendSession`
  - `@ 0x180091400` `ssiTlsSuspend`
- **What**:
  - **ClientHello** always has a 7-byte session id. It holds the stored id if the
    TLS context has one, otherwise 7 zero bytes from the zeroed buffer.
  - **ServerHello** counts as a resumption only if all of these hold: the context
    has a stored id, the server's id is 7 bytes long, and it equals the stored id
    (`palCryptoVerifyMac`). Then the cipher must equal the previous one, the key
    block is derived again (`FUN_180093930`), and Finished is expected next.
    Otherwise it's a full handshake and the new id is stored.
  - **Resumption is reachable only when the context is reused.**
    `tudorTlsSessionStart` reuses `hSensor->pTLSCtx` when the host still has a
    secure session but the sensor reports none. In that case it calls
    `tudorTlsSuspendSession(…, 0)` → `ssiTlsSuspend`, which resets the state and
    keeps the id and keys, before running `ssiTlsEstablish` on the same context.
    A fresh context (`tudorTlsInitCtx`) has no id, so it always does a full
    handshake.
  - `tudorTlsDataGet` / `tudorTlsDataRestore` have no callers.
- **For libfprint**: a new `TlsSession` is made on every open
  (`synatlsmoc.c`, `tls_session_new`) and establishes once. That's the
  fresh-context case: offer 7 zero bytes and never resume. That matches Windows.
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-11: Windows capture sequence and finger events

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x18000c4f8` `CCaptureImage::CheckForFingerPresence`
  - `@ 0x18000c7d8` `checkForFingerPresence`
  - `@ 0x18007b720` `startCapture`
  - `@ 0x18007a7a0` `tudorCaptureProcess`
  - `@ 0x18007c920` `serializeEventsFromMask`
- **What**: the sequence before and during a capture.
  1. `CheckForFingerPresence` configures FINGER_DOWN | FINGER_UP (vfm mask
     0x180 → event types 1 and 2) and waits for the first of either. If that is
     FINGER_DOWN, the finger is already on the sensor: it reconfigures to
     FINGER_UP only and waits for the lift. It then sets the mask back to none.
  2. `tudorCaptureStart` → `startCapture` configures **FRAME_READY only** (0x1000 →
     type 24), then sends FRAME_ACQ (trigger 1).
  3. `tudorCaptureProcess` waits for that event, then polls
     `tudorCaptureFrameReadyStatusGet`: bit 0/1 means a finger was detected,
     bit 1 means the frame is ready. The event mask isn't reconfigured between
     FRAME_ACQ and the frame being ready.
- **Double-checked details**:
  - `CBiometricDevice::CaptureImage` (`@ 0x1800022cc`) runs the presence check
    before each capture. It skips it only when an adapter callback (vtbl+0xc0)
    returns true; I haven't identified that case, possibly a wake by finger.
  - **EVENT_CONFIG (0x86)** (`tudorCmdEventConfig @ 0x180083ab0`, 37 bytes): the
    mask `1 << type` goes into u32 words 0 and 4 only (bytes `[1..4]` and
    `[17..20]`). Words 1–3 and 5–7 are 0, and `[33..36]` is 4 when no events are
    set, otherwise 0. The reply's u16 at `[64]` is the current event sequence
    number. libfprint writes the mask into all 8 words.
    - Checked in the disassembly (`0x180083ca4`–`0x180083d34`): the word index
      is `(type / 128) / 4` (signed division), which is 0 for every byte value.
    - The buffer comes from `allocate_TLSCtx` (`@ 0x180086c10`), which zeroes it
      with `ssi_open(p, 0, n)` = memset. The user's name `allocate_TLSCtx` looks
      wrong: it allocates a zeroed command buffer and writes the command byte.
  - The frame-ready status (`tudorCaptureFrameReadyStatusGet @ 0x18007b370`) is
    the USB driver's cached 7-byte interrupt packet (`VCSDRV_IOCTL_GET_DEVICE_STATE`),
    not a sensor command. Byte 0 == 2 means a finger is detected; a change in
    byte 1 since FRAME_ACQ means a frame is ready.
  - Capture-time event reads (`get_ev_status @ 0x18007b850`) only look for
    FRAME_READY and ignore every other event.
- **Inference**: step 1 accepts either event as its first, so the sensor most
  likely reports the current finger state as soon as the mask is set. The lift
  that Windows requires before FRAME_ACQ suggests trigger 1 needs a fresh finger
  touch, but that is firmware behaviour and can't be shown from the DLL.
- **libfprint differs**: after FRAME_ACQ it reconfigures to
  FINGER_DOWN | FRAME_READY. That reply resets `event_seq_num` and `event_recv`,
  and it then requires `event_recv == event_mask`. A finger-down that lands
  between FRAME_ACQ and that reply is dropped, so the wait needs another touch.
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-11: FRAME_ACQ acq flags in the 0x00D8 driver (v110)

- **Where**: `synaWudfBioUsb110.dll` (6.0.129.1110; the only surveyed INF that
  lists PID 00D8). It isn't in the Ghidra project, so this was read through REA
  and the function names are mine:
  - `@ 0x180089580` `tudorCaptureStart`
  - `@ 0x180066350` `vfmUtilCaptureImage`
  - `@ 0x18000f8c4` `CCaptureImage::CaptureImage`
  - `@ 0x180002b68` `CBiometricDevice::CaptureImage`
- **What**: the acq-flags formula differs from v111.

  | build | enroll | verify / identify |
  | ----- | ------ | ----------------- |
  | v104  | 0      | 0 |
  | v111  | 12 (`0x000c`) | 4116 (`0x1014`) |
  | v110  | 12 (`0x000c`) | `0x0014`, or `0x1014` when the caller sets an extra flag |

  How v110 builds the flags:
  - `tudorCaptureStart`: `captureFlags & 8` → `base | 8`. Otherwise
    `base | 0x10`, or `base | 0x1010` when `captureFlags & 0x40`.
  - `vfmUtilCaptureImage`: mode bit `0x10` → captureFlags `|= 0x40`.
  - `CCaptureImage::CaptureImage(purpose, extra)`: mode is `purpose & 0x1c ? 12 : 4`,
    plus `| 0x10` when `extra` is set.
  - `CBiometricDevice::CaptureImage` sets
    `extra = (this+0x6ea == 0) && (adapter vtbl+0x40 returned non-NULL)`. What
    this means is still unknown.
- **Consequence**: no Windows build sends 4116 for enroll. libfprint commit
  `2f8b3e7` ("add support for 06cb:00d8") set `CAPTURE_FLAG_AUTH = 15`. Because
  `send_frame_acquire` tests `== CAPTURE_FLAG_AUTH`, verify kept sending 4116 and
  only **enroll** changed (12 → 4116). That isn't what 00D8's own Windows driver
  sends.
- **Status**: unverified (REA decompilation, not cross-checked in the project)
- **Ghidra changes**: none (REA session only)

### 2026-10-11: TLS alerts: Windows only ever sends close_notify

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x1800957c0` (`FUN_1800957c0`, builds an alert record)
  - `@ 0x180092f00` (`ssiTlsAlertNotify`)
  - `@ 0x180088c60` (`tudorTlsSessionClose`)
  - `@ 0x180089260` (`tudorTlsSuspendSession`)
  - `@ 0x180095c90` (`ssiTlsReceiveData`)
- **What**:
  - **Sending.** `FUN_1800957c0` has one caller, `ssiTlsAlertNotify`, which always
    passes description 0 (close_notify). The builder would use level 2 (fatal)
    for 10, 20, 40 and 47, but nothing calls it with those values.
    `ssiTlsAlertNotify` is called only from:
    - `tudorTlsSessionClose`, when its 2nd argument is 1, the provision state is 3
      and `tudorTlsSensorSessionStatusGet` says the sensor still has a session
      open;
    - `tudorTlsSuspendSession`.
  - **Errors.** On a protocol error, `ssiTlsReceiveData` sets a local alert
    description (10 unexpected_message, 47 illegal_parameter, or whatever the
    handshake/decrypt helpers return). It then **only logs it** ("TLS alert,
    description: %d"), sets a flag on the context and returns
    `SENSOR_MALFUNCTIONED`. No alert is sent to the sensor.
  - **Received alerts:**
    - level 1, description 50: treated as "TLS Session is successfully resumed"
      (non-standard; record type becomes 0xff);
    - description 0: logged as "Session close confirmed by the sensor". Nothing is
      sent back and no error is returned;
    - description 42 (bad_certificate): returns
      `SENSOR_NEED_TO_RESET_OWNER` ("Host has bad certificate");
    - anything else: returns `SENSOR_MALFUNCTIONED`, without replying.
- **Evidence**: decompilation of the functions above. A search for the
  alert-description fields finds no other writers.
- **Status**: unverified. Relevant to CMT-3 and NIT-8 in
  `libfprint/DRIVER_ISSUES.md`.
- **Ghidra changes**: none

### 2026-10-11: Certificate size depends on its magic (400 or 184 bytes)

- **Where**: `synaWudfBioUsb111.dll`:
  - `@ 0x1800948b0` (`FUN_1800948b0`, builds the TLS Client Certificate
    message, called from `handleServerHelloDone`)
  - `@ 0x180099080` (`ssiTlsVerifyDeviceCertificate`)
  - `@ 0x180098340` (`FUN_180098340`, ECDH client key exchange)
- **What**: there are two certificate layouts, and the leading u16 magic
  selects one:

  | field              | magic `0x5f3f`   | any other magic  |
  | ------------------ | ---------------- | ---------------- |
  | total size         | 400              | 184 (`0xb8`)     |
  | pub x / y (68 B)   | `+0x04` / `+0x48` | `+0x08` / `+0x4c` |
  | signed range       | `[0, 0x8e)`      | `[0, 0x90)`      |
  | signature length   | u16 at `+0x8e`   | u32 at `+0x90`   |
  | signature          | `+0x90`          | `+0x94`          |

  The signature length is used as read; Windows doesn't bound-check it.
- **Evidence**:
  - `FUN_1800948b0`: `if (magic == 0x5f3f) len = 400; else len = 0xb8;`, then
    the cert-list length fields and the copy use `len`.
  - The two other functions branch on the same magic and use the offsets in
    the table.
- **Status**: unverified. The driver only accepts `0x5f3f`
  (`sensor_certificate_from_raw`). Which sensors, if any, use the other layout
  is unknown. This is relevant to CMT-2 in `libfprint/DRIVER_ISSUES.md`.
- **Ghidra changes**: none

### 2026-10-10: Sensor status words → VCS_RESULT codes

- **Where**:
  - `synaWudfBioUsb136.dll @ 0x1800d4c00` (`result_code_to_str`; its name
    table is at `0x1801e37b0`)
  - `synaWudfBioUsb111.dll @ 0x180087f20` (`fwReplyConvertToErrorCode`)
  - `synaWudfBioUsb136.dll @ 0x1800a0ad0` (the same converter in v136)
- **What**: the full map is in `rev/notes/result-codes.md`. It contains:
  - all 71 `VCS_RESULT_*` names with their values. No build in the DLL
    survey has any other `VCS_RESULT_*` name.
  - the sensor-status-word → `VCS_RESULT` conversion.
    - v136 adds status `0x315` (TLS internal failure), `0x689` (operation
      denied), and `0x70d` / `0x70e` (unnamed `0xe0` / `0xe1`).
    - Status `0x48c` is never converted. `tudorSecureBioConnect` sends the
      command again (up to 3 tries).
    - Any status not in the map becomes `VCS_RESULT_SENSOR_MALFUNCTIONED`
      (`0xca`).
    - Codes `0xdc`, `0xdd`, `0xdf`, `0xe0` and `0xe1` have no name in any
      build.
- **Evidence**:
  - the decompiled table walk (200 entries of 16 bytes);
  - the table parsed from the DLL file with pefile;
  - both converters decompiled.
- **Status**: unverified
- **Ghidra changes**: none

### 2026-10-10: v136 IPT provisioning, basic (PSK) vs advanced pairing

- **Where**: `synaWudfBioUsb136.dll` (6.0.39.1136, x64; imported into the
  project root as `/synaWudfBioUsb136.dll`, because `/other_versions` didn't
  exist and ReVa can't create folders):
  - `ai_tudorSensorIptProvision @ 0x1800a4980` (tudorIoctl `FUN_180094c60`
    case 0x23)
  - `FUN_1800a5430` (IPT gate), `FUN_1800a54c0` (patch + provision)
  - `ai_tudorCmdDownloadBootLoaderPatch @ 0x180098d60` (cmd 0x7d)
  - `FUN_180098fc0` (sends cmd 0x0e)
  - `ai__tudorBootLoaderModeEnter @ 0x1800a55f0`,
    `ai__tudorBootLoaderModeExit @ 0x1800a5730`,
    `ai__tudorSetPipeTimeouts @ 0x1800a5870`
  - `ai_vfmSensorIptProvision @ 0x18004d560`,
    `ai__vfmUtilSensorIptProvision @ 0x180067fe0` (called from the vfmUtil
    session path `FUN_180068dc0`)
  - `ai_CBiometricDevice_DoIptProvision @ 0x180004080`,
    `ai_CBiometricDevice_InitAndGetState @ 0x1800052d4`
  - `FUN_18009ef10` (send/receive, the tudorSecureBioConnect equivalent; cmd id
    is the 2nd argument)
  - `FUN_18008c280` (sensor-info flags), `ai_tudorCmdGetVersion @ 0x180097bb0`,
    `ai_tudorCmdGetVersion2 @ 0x180098770` (cmd 0xb4), `ai__tudorInitDevice @
    0x18008d0b0`
  - `ai_tudorTlsSessionStart @ 0x1800a2520`, `ai_tudorSecurityDoPair @
    0x1800a7230`, `ai__tudorSecurityBasicPairing @ 0x1800a9ba0`,
    `ai__tudorSecurityAdvancedPairing @ 0x1800a99f0`, `ai__tudorCmdDoPairBasic
    @ 0x1800aa3d0`, `ai__tudorUnwrapPsk @ 0x1800aadf0`,
    `ai__tudorDecVerifyWithAES_GCM @ 0x1800aaa80`
- **What**:
  - **v136 does send VCSFW_CMD_PROVISION (0x0e).** This **contradicts** the
    v111 entry's "Windows never provisions", as far as v136 goes. (The v111
    finding still holds for v111 itself: there `sendCmdProvision` has no
    callers.)
  - **IPT provisioning** (`ai_tudorSensorIptProvision`) is a resumable state
    machine. Its state is a u32 at `hSensor[0x15]`:
    - 0 CHECK: GET_VERSION (0x01). If the `interface` byte (reply byte 0x19,
      `SensorVersionParam_t.interface`) has **bit 3 (0x08) clear**, go to 1;
      otherwise go to 4, with nothing to do.
    - 1 ENTER_BL: proto IOCTL 0x68 with the 8-byte buffer
      `00 00 00 00 00 00 01 00` (bootloader enter), then TLS close, then
      `_tudorInitDevice`. If that returns action 3, it returns to the caller
      and resumes later.
    - 3 PATCH: sets pipe timeouts to 180000 ms, then:
      - **cmd 0x7d** BOOTLDR_PATCH. Payload is a built-in 48836-byte
        (0xBEC4) blob at `0x1801acfb0` (descriptor `DAT_1801db810`). It starts
        `07 00 00 00 00 00 00 00 0e 00 00 00 ...`; from about +0x24 on it is
        high-entropy, probably signed and/or encrypted.
      - **cmd 0x0e** PROVISION. Payload is u32 LE **0x97** (buffer
        `0e 97 00 00 00`). v111's dead `sendCmdProvision` used 0x17;
        0x97 = 0x17 | 0x80.
      - Then the timeouts are restored.
    - 2 EXIT_BL: IOCTL 0x68 with byte 6 = 0 (bootloader exit), then
      `_tudorInitDevice`.
    - 4 DONE, then 6.
    - 5 ERROR: retries from 2 if the product id is F/G/B/C (bootloader
      ids); otherwise ends.
  - The full set of command IDs sent via `FUN_18009ef10`:
    0x01, 0x05, 0x07, 0x08, 0x0e, 0x19, 0x39, 0x3e, 0x3f, 0x40, 0x41, 0x57,
    0x7d, 0x7f, 0x80, 0x81, 0x82, 0x86, 0x87, 0x8b, 0x8e, 0x93 (two variants),
    0xa6, 0xaa, 0xab, 0xac, 0xae, 0xaf, 0xb4, 0xe5. There is **no 0x10
    (RESET_OWNERSHIP) and no 0x4f (TAKE_OWNERSHIP_EX2)**; those appear only
    in the name table `FUN_18009f5a0`.
  - **When it runs:** `InitAndGetState` calls `DoIptProvision` on every
    device init, right after the device-update loop. It is skipped only while
    `PairingInProcess` or `UnairingInProcess` is set.
    - No registry switch or provision-state check gates it. The only gate is
      GET_VERSION `interface` bit 3.
    - `vfmUtil` (`FUN_180068dc0`) calls it the same way after device
      reset/update.
    - `DoIptProvision` loops `vfmSensorIptProvision` → tudorIoctl 0x23 until
      the action is 0. Action 2 means repeat after a delay; action 3 means
      hard reset.
    - On action 3 it saves the state through vfm get-param 0x6e into
      `IptProvosionContext` (sic), sets `IptProvisionInProcess=1` and returns.
      On the next init it restores the state (set-param 0x6e) and continues.
    - On success it clears `IptProvisionInProcess` and resets the failure
      counter. On failure it increments the counter, capped at 5, and writes it
      as `iptProvisionFailureCount`. I saw nothing that stops retrying at 5.
    - `IptProvisionFailureCount` is also one of five persisted counters
      (`FUN_18000b8b8` / `FUN_18000ca38`).
  - **Provision state after IPT:** nothing in host code writes the provision
    state. `hSensor+0x1e` is only filled from GET_VERSION byte 37 & 0xf in
    `FUN_18008c280`, which is re-run by `_tudorInitDevice` after IPT. Whether
    0x7d + 0x0e(0x97) moves the sensor to 3 is decided by firmware, and is
    **not proven**.
  - **What "IPT" stands for:** no expansion anywhere in v136 strings. There are
    no "Intel", "PTT" or "Trust" strings. The only other hit is `sapIpt`, the
    trace-module name of the `InSensor` module (`FUN_1800ca2c0`). Unknown.
  - **Sensor flags** (`FUN_18008c280`, copied to `hSensor+8`):
    - +0x18 product id
    - +0x1a `interface & 0x20` (if clear and not in bootloader: "Deny:
      Production driver ...")
    - +0x1b `platform & 4`
    - +0x1c `security & 1` (advanced security)
    - +0x1d `security & 4` (new; usage not traced)
    - +0x1e `provisionState & 0xf`
  - **TLS** (`ai_tudorTlsSessionStart`):
    - Provision state 0, 1 or **4** logs "Sensor is not provisioned. Unable to
      establish TLS" and returns 0. That means plaintext, the same as v111.
    - In state 3 the TLS type is `advanced ? 1 (ECC) : 2 (PSK)`. **PSK TLS is
      live in v136** (it was dead code in v111).
  - **Pairing** (`ai_tudorSecurityDoPair`):
    - It requires provision state 3; otherwise it logs "Skipping pairing:
      sensors is not secure" and returns success.
    - Then the GET_VERSION `security` bit 0 picks the mode:
      - 1: "Pairing in advanced security mode." → ECC certificate pairing, as
        in v111 (PAIR 0x93, 0x190-byte payload, `FUN_1800a80a0`).
      - 0: "Pairing in basic security mode." →
        `_tudorSecurityBasicPairing`. v111 returned an error here.
  - **Basic pairing:**
    - Request: PAIR **0x93** with a 0xb4-byte payload:

      | Offset | Content |
      | --- | --- |
      | +0 | Rh, 32 random bytes |
      | +0x20 | u32 0x17 |
      | +0x24 | u32 key bytes (`roundup32(bits)/8`) |
      | +0x28 | u8 0 |
      | +0x2c | host pub X (0x44 bytes) |
      | +0x70 | host pub Y (0x44 bytes) |

      Response buffer size is `0x100 + 0x346`.
    - Reply, offsets after the 2-byte status:

      | Offset | Content |
      | --- | --- |
      | +0, +400 | two sensor certificates, verified against the Synaptics key |
      | +0x194 / +0x1d8 | sensor ECDH pub X/Y |
      | +0x320 | 32 bytes, stored as container tag 6 |
      | +0x340 | u32 wrapped-PSK length |
      | +0x344 | wrapped PSK |
    - **The PSK comes from the sensor.** `_tudorUnwrapPsk` does:
      1. ECDH(host private key, container tag 2; sensor pub);
      2. palPRF → 32 bytes;
      3. palSymKeyGen(label `"WRKP"`, 4 zero bytes, 64 bytes); bytes
         32..63 are the AES-256-GCM key;
      4. decrypts the blob, laid out as ct | IV[12] | tag[16] | 8-byte
         trailer, where the u32 at n-4 equals the ct length.
    - The plaintext PSK is stored as container tag 5, which is what the TLS
      PSK mode uses (`SSI_STORAGE_PSK_ID`).
- **Evidence**:
  - `FUN_1800a54c0`: `FUN_180098d60(param_1,&DAT_1801db810)` then
    `FUN_180098fc0(param_1,0x97)`.
  - `FUN_180098fc0`: `FUN_18009f4d0(0xe,5)`, `*(buf+1)=param_2`,
    `FUN_18009ef10(param_1,0xe,...)`.
  - The name-table case labels sit next to the strings `VCSFW_CMD_PROVISION`
    @ 0x1801d5d40 and `VCSFW_CMD_BOOTLDR_PATCH` @ 0x1801d5ca0.
  - `FUN_1800a5430`: `return (local_21 & 8) == 0`, where `local_21` is offset
    0x17 of `SensorVersionParam_t`, the `interface` field (struct from the v111
    project).
  - `InitAndGetState` calls `DoIptProvision` unconditionally.
  - Strings "Pairing in basic security mode. " @ 0x1801da3a8, "Pairing in
    advanced security mode. " @ 0x1801da3d8, "WRKP" @ 0x1801dae94, "PSK
    Decription failed %d" @ 0x1801dafd8.
- **Contradictions with the v111 entry**:
  1. "Windows never provisions": false for v136. v136 sends PROVISION 0x0e
     (after a bootloader patch) on any sensor whose GET_VERSION `interface`
     bit 3 is clear, automatically at every driver init.
  2. "The sensor never needs Windows once": **no longer safe to claim**. A
     sensor that was never run under a v136-class driver may have
     `interface` bit 3 clear and may never have had this IPT step applied. We
     don't know whether that changes provision state or anything else.
  3. "Without advanced security pairing returns an error": in v136 such
     sensors pair in basic mode, using PSK TLS.
  4. "PSK is dead code": it is live in v136.
  5. Unprovisioned (0/1, now also 4) still means plaintext with no TLS in v136,
     the same as v111.
- **Implications for libfprint**:
  - Sensors without advanced security that are provisioned (state 3) can be
    paired with basic PAIR 0x93 plus PSK TLS. This is not implemented.
  - Check what `interface & 0x08` reads on real sensors. If it is clear, the
    sensor has probably not had IPT done. Replicating it would mean shipping
    Synaptics' 48 KB patch blob.
- **Status**: unverified. The IPT command sequence and the pairing paths are
  proven from code. The effect on provision state and the meaning of "IPT" are
  inferred or unknown.
- **Ghidra changes** (`/synaWudfBioUsb136.dll` only):
  - Renamed `FUN_` functions with `ai_` names taken from their log strings:
    all the `ai_*` functions listed above.
  - `[AI]` plate comments on `ai_tudorSensorIptProvision`, `FUN_1800a54c0`,
    `FUN_180098fc0`, `FUN_18009ef10`, `FUN_1800a5430`, `FUN_18008c280`,
    `ai_CBiometricDevice_DoIptProvision`, `ai_tudorSecurityDoPair`,
    `ai__tudorSecurityBasicPairing`, `ai__tudorUnwrapPsk` and
    `ai_tudorTlsSessionStart`.
  - Tag `AI` on all of them.
  - `/synaWudfBioUsb111.dll` untouched.

### 2026-10-10: Provisioning, pairing and "does it need Windows once?"

- **Where**: `synaWudfBioUsb111.dll` unless noted:
  - `sendCmdProvision @ 0x1800825f0`
  - `tudorTlsSessionStart @ 0x180088150`
  - `_tudorInitDevice @ 0x180077db0`
  - `FUN_1800774a0` (reads the provision state from GET_VERSION byte 37 & 0xf)
  - `tudorSecurityDoPair @ 0x18008a770`
  - `tudorSecurityDoUnPair @ 0x18008b8e0`
  - `CBiometricDevice::InitAndGetState @ 0x1800044a0`
  - `ProcessPairing @ 0x180008958`
  - `DoUnpairing @ 0x180003ab0`
  - `OnResetOwnership @ 0x1800137bc`
  - `tudorIoctl @ 0x18007f180`
  - `smtWithPairing @ 0x18008ea10`
  - palSecureWrap backend `FUN_18006c4c0`
  - `synaFpAdapter111.dll`: `_SensorAdapterResetOwnership @ 0x180008c50`
- **What**: the vocabulary.
  - **Provision state:** a property of the sensor, set outside the host
    driver. The values are 0/1 (not provisioned) and 3 (provisioned).
    The driver only ever *reads* it. In the driver it gates:
    - TLS start: 0/1 means no TLS.
    - Pairing: requires 3.
    - Unpairing: requires 3.
    - The close-notify alert sent when TLS closes: requires 3.

    What it means inside the sensor is **not visible in host code**. (An
    earlier version of this entry said "factory identity / certificate";
    that was an inference, now retracted.)
  - **Advanced security:** GET_VERSION `security` byte, bit 0
    (`FUN_1800774a0`, stored in `hSensor->advancedSecuritySupported`). It is
    read only by `tudorSecurityDoPair` and `tudorSecurityUpdatePairedData`.
    Without it, pairing returns an error. `tudorTlsSessionStart` does not check
    it, but ECC TLS needs pairing data, so in practice TLS needs both flags.
  - **TLS modes:** `tudorTlsInitCtx(hSensor, tlsSecurityType)` supports
    - 1 = ECC: sensor cert (tag 3), host cert (tag 1), private key (tag 2)
      and tag 4, from the pairing data;
    - 2 = PSK: `SSI_STORAGE_PSK_ID`, tag 5, 64 bytes.

    `tudorTlsSessionStart` always passes 1 (its `isProvisioned` variable is
    initialised to 1 and only ever set to 1), so PSK is dead code in v111.
  - **Synaptics sensor-signing key** (`tudorSecurityGetSSPubKey`): chosen
    from a built-in table by firmware major, minor and a device-info flag
    byte at offset 0x12. It is not chosen by provision state.
  - **Pairing:** what the host does. It generates an ECC host key pair,
    builds a host certificate, sends PAIR (0x93), and receives and checks the
    sensor certificate. The pairing data is a tag/value container: version,
    host cert, private key, sensor cert, and so on.
- **What the Windows driver does**:
  1. **It never provisions.**
     - `sendCmdProvision` (0x0e, payload u32 `7|0x10`) has no callers. Only a
       `.pdata` entry references it.
     - RESET_OWNERSHIP (0x10) and TAKE_OWNERSHIP_EX2 (0x4f) appear only in the
       command-name table. Nothing sends them.
     - The full list of command IDs sent via `tudorSecureBioConnect` contains
       none of them.
     - The only raw passthrough is `tudorIoctl` case 3
       (`tudorSendAnyCommand`), which is used by the matcher/storage layer and
       the TLS close alert.
  2. **Unprovisioned (0/1) means plaintext.**
     - `tudorTlsSessionStart` logs "Sensor is not provisioned. Unable to
       establish TLS", never creates a TLS context, and **returns success**.
     - Every later command then goes over USB unencrypted:
       - `tudorEncryptCommand @ 0x180088a20` with no TLS context logs "TLS
         context is not initialized", returns 0 and leaves the buffer
         untouched.
       - `tls_decrypt_msg @ 0x180088b40` does the same for replies.
     - This is not a deliberate "unsecure mode"; the driver just carries on
       without a session. Nothing tries to change the state.
     - Caveat: this is host code only. The firmware may still reject some
       commands without a secure session or paired host (enroll, match,
       storage). Untested; it needs a sensor in state 0/1.
  3. **Provisioned (3)**, in `tudorTlsSessionStart`:
     - Pairing data comes from memory. If it isn't there, it is read from the
       sensor host partition (tag 2, `getTagFromContainerWithHashes`).
     - If neither works, the result is `VCS_RESULT_SENSOR_NEED_TO_RESET_OWNER`.
     - `InitAndGetState` then tries the copy in
       `HKCU\Software\Synaptics\PairingData`. If init then succeeds, it
       backs the data up to the sensor (`BackupPDtoSensor`).
     - Otherwise it goes to state 2: `DoUnpairing`.
  4. **"Unpair" and "reset ownership" never touch the sensor.**
     - `DoUnpairing` → `vfmSecurityUnPair` → `tudorSecurityDoUnPair` only
       closes TLS and frees the host-side data. It requires state 3.
     - The WBF `_SensorAdapterResetOwnership` → IOCTL 0x442040 →
       `OnResetOwnership` → `DoUnpairing`, so it is the same thing.
  5. **Re-pair:** `ProcessPairing` then runs `DoPairing` →
     `tudorSecurityDoPair`.
     - It only proceeds in state 3. Any other state logs "Skipping pairing:
       sensors is already paired or unsecure" and returns success.
     - It requires advanced security; otherwise it returns an error.
     - After PAIR it starts TLS and writes the wrapped pairing data to the
       sensor host partition.
     - So **a state-3 sensor accepts a fresh PAIR whenever the host has lost
       its data.** Windows relies on this.
  6. **The wrapping is Windows DPAPI.** `palSecureWrap` → `CryptProtectData`.
     Neither the registry copy nor the copy on the sensor can be unwrapped
     outside that Windows install.
  7. **Command 0xa6** (`smtWithPairing`, `tudorIoctl` 0x1d) sends a 32-byte
     host nonce and gets back device certs/hashes, to which the Windows Hello
     certificates are appended. It looks like Microsoft SDCP / Enhanced
     Sign-in Security, not provisioning.
- **Superseded in part.** The v136 entry above shows that other Windows
  builds DO send PROVISION, via IPT provisioning, on sensors whose GET_VERSION
  `interface` bit 3 is clear. The answer below holds for the v111 driver
  only.
- **Answer to "must the sensor be started on Windows once?"**: **No, as far as
  the host driver can show.**
  - Windows has no code path that provisions a sensor. A sensor that is
    unprovisioned under Linux is just as unprovisioned under Windows, which
    would only run it without TLS.
  - A provisioned (3) sensor needs only a PAIR, which libfprint already does
    itself (`OPEN_SEND_PAIR`).
  - Nothing Windows leaves behind is usable from Linux anyway, because of
    DPAPI.
  - The one thing Windows may do that Linux doesn't is a firmware/config
    update (`DoDeviceUpdate`). Nothing in it touches the provision state.
  - Limit: this shows what the *host* code does. It can't rule out that
    firmware changes state on its own, e.g. after a firmware update. That
    would need testing on hardware.
- **Implications for libfprint**:
  - `OPEN_LOAD_PAIRING_DATA` fails for 0/1 sensors. Windows instead runs them
    in plaintext.
  - The guard reads `provisioned || advanced_security`. Windows needs
    **both** to pair, and needs only provisioned for TLS.
  - Re-pairing on Linux replaces Windows' pairing on the sensor. Effects on
    existing enrollments are still an open question.
- **Status**: unverified
- **Ghidra changes**:
  - `[AI]` plate comments and tag `AI` on `sendCmdProvision`,
    `tudorTlsSessionStart`, `tudorSecurityDoPair`, `smtWithPairing` and
    `FUN_18006c4c0`.

### 2026-10-10: captureFlags bits, v104 vs v111

- **Where**: `synaWudfBioUsb104.dll` (fresh REA import, no annotations):
  - `tudorCaptureStart @ 0x18006e730`
  - `tudorCaptureProcess @ 0x18006eae0`
  - `tudorCaptureFrameRead @ 0x18006fbd0`
  - `sendCmdFrameAcq @ 0x180077050`
  - `vfmUtilCaptureImage @ 0x1800501e0`
  - `CCaptureImage::CaptureImage @ 0x18000d894`

  Compared against the v111 functions in the FRAME_ACQ entry below.
- **What**: captureFlags is the value libfprint calls `CAPTURE_FLAG_*`. Its
  bits:

  | bit | v104 (still reads images) | v111 (match on chip) |
  | --- | --- | --- |
  | 0x1 | with 0x2 selects the mode (see below); frame read fails with "The last frame is not received" (0xca) if the frame lacks the last-frame flag | mode selection only |
  | 0x2 | with 0x1 selects the mode; with trigger 1, reports "finger detected" (status 2) before the frame is ready | same |
  | 0x4 | run image post-processing (`tudorFramePostProcess`) | always set (7, 15); no reader left |
  | 0x8 | set for enroll, but unused in the tudor layer, so it has no effect on the wire | enroll: acq flags `\|= 8`, else `\|= 0x1010` |

  Higher bits are rejected by `vfmCaptureStart` (mask 0x3f).

  The caller side is identical in both versions: WBF purpose ENROLL* gives
  captureFlags 15, verify/identify gives 7, always 1 frame, trigger 1.
  The FRAME_ACQ packet layout is also identical. Only the acq flags at
  `[1..4]` changed:

  | mode | v104 acq flags | v111 acq flags |
  | --- | --- | --- |
  | 1 (N frames) | `N == 0 ? 1 : 0` | `N == 0 ? 1 : 4`, then the bit3 rule |
  | 2 (single, finger-triggered) | `0` | `4`, then the bit3 rule |
  | 3 | `1` | `1`, then the bit3 rule |

  So v104 sent the same packet for enroll and verify (flags 0). In v111:
  - acq bit 0x1 consistently means "no frame count / open-ended".
  - acq bit 0x4 means "finite frame count".
  - acq bits 0x8 and 0x1010 are new enroll-vs-match options, presumably
    telling the firmware what the on-chip image is for.
- **Status**: unverified
- **Ghidra changes**: none. v104 is not in the `fingerprint` project.

### 2026-10-10: VCSFW_CMD_FRAME_ACQ (0x80) request layout

- **Where**: `synaWudfBioUsb111.dll`
  - `sendCmdFrameAcq @ 0x1800832c0`: builds the packet
  - `tudorCaptureStart @ 0x18007a3a0`: maps captureFlags to the packet arguments
  - `vfmUtilCaptureImage @ 0x180057110`, `vfmUtilStartCapture @ 0x1800581e0`:
    map the caller's mode bits to captureFlags
  - `CCaptureImage::CaptureImage @ 0x18000c384`: chooses enroll or non-enroll
- **What**: the packet is little-endian, with an 8-byte block appended unless
  `flags & 2`:

  | off | size | value |
  | --- | --- | --- |
  | 0 | u8 | `0x80` |
  | 1 | u32 | acq flags |
  | 5 | u32 | number of frames |
  | 9 | u16 | `1` (block header) |
  | 11 | u8 | `0` (block header) |
  | 12 | u8 | `8` (block header; possibly the block length) |
  | 13 | u8 | `1` in modes 2/3, `0` in mode 1 |
  | 14 | u8 | trigger mode (`1` = finger-triggered) |
  | 15 | u8 | `1` in mode 2 only |
  | 16 | u8 | `0` |
  | 17..24 | | mode 3 only: `01 00 00 0c 14 00 02 00` |

  The packet is 9, 17 or 25 bytes long. The reply is just the 2-byte status.
  Status `0x6ea` (`RESPONSE_PROCESSING_FRAME`, internally mapped to 0xdf) is
  retried up to 3 times with a 100 ms sleep between tries.

  Chain from Windows Biometric Framework (WBF) purpose to packet:

  | caller | captureFlags | mode | numFrames | acq flags | trigger |
  | --- | --- | --- | --- | --- | --- |
  | `CaptureImage`, purpose & 0x1c (any ENROLL) | 15 | 2 | 1 | `4 \| 8` = **12** | 1 |
  | `CaptureImage`, verify / identify | 7 | 2 | 1 | `4 \| 0x1010` = **0x1014 (4116)** | 1 |
  | `OnArmWakeFromSxByFinger` → `vfmUtilStartCapture(4)` | 7 | 2 | 1 | 0x1014 | 1 |
  | `vfmUtil*(2)`: no live caller | 5 | 3 | 0 | `1 \| 0x1010` | 1 |
  | `vfmUtil*(1)`: no live caller | 0 | 1 | caller value | `1 \| 0x1010` if 0 frames, else `4 \| 0x1010` | 0 |

  **Modes** (the `1_2_3` argument). Only mode 2 is reachable in v111:
  - `vfmUtilCaptureImage` is only called with 4 or 12.
  - `vfmUtilStartCapture` is only called with 4 (the other caller,
    `vfmUtilFrameRead`, has no callers).
  - `sendFrameRead` (FRAME_READ) and `sendCmdFrameStream` (FRAME_STREAM,
    0x8b) also have no callers, so on this match-on-chip build the image never
    leaves the sensor.

  What each mode probably is (inferred from the arguments, not confirmed):
  - **Mode 1** (captureFlags bit0 clear): the only mode allowed with trigger 0
    (`vfmCaptureStart` returns NOT_IMPLEMENTED for bit0 + trigger 0). It takes
    the caller's frame count, so it is likely an immediate, non-finger-triggered
    raw/test capture of N frames.
  - **Mode 2** (bits 0 and 1): one frame, finger-triggered. With trigger 1 it
    sets `CaptureCtx.field22_0x2c`, which makes `tudorCaptureProcess` report
    status 2 (finger detected) once frame-state bits `& 3` appear, before the
    frame is ready.
  - **Mode 3** (bit0, not bit1): frames 0 (unbounded?), flags 1, plus the
    extra `0c` block (u16 20, u8 2). Paired with `vfmUtilFrameRead`, which
    reads a frame and restarts the capture, so it is likely continuous or
    streaming acquisition, possibly navigation (`hSensor->state == 2` is "NAV").

  tudorCaptureStart rules:
  - bit0 clear → mode 1, numFrames comes from the caller, flags = 4 (or 1 if
    numFrames == 0).
  - bit0 and bit1 set → mode 2, numFrames 1, flags 4.
  - bit0 set, bit1 clear → mode 3, numFrames 0, flags 1.
  - Then bit3 set → `flags |= 8`, bit3 clear → `flags |= 0x1010`.
  - `vfmCaptureStart` rejects captureFlags with bits above 0x3f set, and
    triggerMode ≥ 3.
- **Evidence**: decompilation of the functions above. The CaptureImage purpose
  test is `(purpose & 0x1c) != 0 ? 12 : 4`. 0x1c matches the WBF
  `WINBIO_PURPOSE_ENROLL*` bits, and the outer `CBiometricDevice::CaptureImage`
  compares the same byte against 2 (IDENTIFY) and 4 (ENROLL).
- **Implications for `libfprint`** (LOG-2): the libfprint driver's verify/identify
  packet (4116, nframes 1, `01 00 00 08 01 01 01 00`) already matches Windows.
  Enroll should send flags **12** with the same tail. Today it sends 4116,
  because `CAPTURE_FLAG_AUTH == CAPTURE_FLAG_ENROLL`. Meaning of the
  differing bits:
  - Enroll sets `0x8`.
  - Non-enroll sets `0x1010`.
  - What each bit means on the sensor side is still unknown.
- **Status**: unverified
- **Ghidra changes**:
  - `[AI]` plate comments on `sendCmdFrameAcq`, `tudorCaptureStart` and
    `CCaptureImage::CaptureImage`.
  - Renamed `param_4` → `ai_triggerMode` (sendCmdFrameAcq) and `param_2` →
    `ai_winbioPurpose` (CaptureImage).
  - Tag `AI` on all three functions.
  - In sendCmdFrameAcq, renamed `uVar1` → `ai_u16` (the u16 temp for header
    and value bytes).
  - Created struct `/AI/ai_FrameAcqCmd` (25 bytes; byte arrays, so offsets
    match without packing). Not applied to `toSendData`, which is a
    user-named variable.
  - Incident: the first `rename-variables` call committed the decompiler's
    parameter list, which reset the user's name `numberOfFrames` to `param_5`
    and the type of `param_4` from `undefined` to `BYTE`. The name has been
    restored; the `BYTE` type was left as is.
