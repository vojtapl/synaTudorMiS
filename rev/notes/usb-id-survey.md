# USB ID survey: which Windows-supported PIDs fit `synatlsmoc` (2026-10-11)

AI-run, read-only survey. Nothing from the driver packages was executed;
everything below comes from INF text, DLL bytes and strings, and the libfprint
source and git history.

Abbreviations: `OSD` = `/home/vojtapl/Projects/done/other synaptics drivers`,
`LFP` = `/home/vojtapl/Projects/libfprint`, `HPD` =
`/home/vojtapl/Projects/synaTudorMiS/HP drivers`.

## Method

1. **INFs.** Parsed all 23 `synaWudf*.inf` under `OSD/` and `HPD/` (all are
   UTF-8/ASCII; none is UTF-16). From each I took `DriverVer`, the
   `synaWudfBioUsb*.dll` it installs, every `USB\VID_xxxx&PID_xxxx` and the
   `[Strings]` name it maps to. Commented-out hardware IDs: none. **VID is
   06CB in every entry; no other VID appears.** The other INFs
   (`synaUtilApp_*`, `synaSecureBio*`, `HPSetup.inf`) list no USB IDs.
2. **DLL family.** I classified each line with the existing string survey
   (`rev/notes/dll-survey/table.txt` and `survey.json`: `tudor`/`VCSFW_CMD_`
   counts). Every 6.x INF line except 107-SGX is "Tudor": 105, 110, 111, 117,
   127, 128, 136, 139, 154, 164, 167, 171.
3. **Firmware and key check (new).** `synatlsmoc` accepts a sensor only if
   its firmware is **10.1**. It verifies the sensor certificate with two
   hardcoded keys, `pubkey_v10_1` and `pubkey_v10_1_kf`
   (`LFP/libfprint/drivers/synatlsmoc/synatlsmoc.c:183-226`,
   `sensor_public_keys.h:58-86`). I searched every DLL for these keys (stored
   little-endian) and decoded the surrounding table. Each entry is
   `[fw_major, fw_minor, keyflag]` + x + y. The stride is 0x103 in older
   builds and 0x203 in newer ones. Results:
   - 111 (all builds), 117, 127, 128, 139: `10.1`, `10.1kf`. These are the
     same two keys as libfprint.
   - 110 (6.0.129 / 6.0.130 / 6.0.205), 105 (6.0.73), 136 (6.0.69), 154,
     164, 167, 171: `10.1`, `10.1kf`, `10.2`, `10.2kf` (same keys as 10.1),
     `10.10` (same key as 10.1), and **`10.10kf` with a different key**
     (x starts `74f828…`). For example `OSD/downloads/msucat-6.0.205.1110/x/synaWudfBioUsb110.dll`
     has the table at file offset 0xf0ad0. In
     `OSD/downloads/msucat-6.0.69.1136/x/synaWudfBioUsb136.dll` it is at 0x113720.
   - 5.x usdk5 builds (051/052/061/066/086/102/106/124/146): fw 6.x/8.0 keys
     only. 098: 8.0/8.20. SGX builds: libfprint keys absent or not in a
     table.
   - So every Tudor line can talk to a fw-10.1 sensor with libfprint's keys.
     The newer lines also expect sensors on fw 10.2/10.10. libfprint would
     reject those today (exact major/minor match), and 10.10+keyflag would
     also need the new key.
4. **Command set.** All `VCSFW_CMD_*` names the driver uses
   (`synatlsmoc.h:69-100`) occur in every Tudor line. The newer lines are
   supersets of v111 6.0.66:
   - 110/6.0.205 adds `ENROLL_WBF`, `IDENTIFY_WBF*` and `HW_INFO_GET_TAG_ID_MFW_INFO`.
   - 105/136/164/167/171 add `EXT_COMMAND`, `EXTSIG`, `FLASH_ERASE`, `IMAGE_METRICS` and `MSBM_CONNECT`.
   - 117/128 lack `GET_VERSION2`/`HW_INFO_GET`/`OPINFO_GET`/`SSO`, which libfprint doesn't use.
5. **Cross-checks.**
   - synatlsmoc `id_table`: `LFP/libfprint/drivers/synatlsmoc/synatlsmoc.c:110-121`.
   - upstream `synaptics` (BMKT) `id_table`: `LFP/libfprint/drivers/synaptics/synaptics.c:33-58`.
   - libfprint unsupported list: `LFP/libfprint/fprint-list-udev-hwdb.c:61-77` and `LFP/data/autosuspend.hwdb:371-389`.
   - upstream `synaptics` PID history: `git log` on `LFP`.

### Key caveat: the Windows DLL does not decide the protocol

The same Tudor DLL installs PIDs that libfprint drives with BMKT (upstream
`synaptics`) and PIDs that need the TLS/MiS protocol (synatlsmoc). For example,
v110 lists 00C4/00DF/00F0/0103/0104/0106-0108, which upstream drives with
BMKT, next to 00D8, which works with synatlsmoc. All of them are called
"FS7605/FS7606". v111 likewise lists 0124 (BMKT upstream) next to
00C9/00E7/00FF. None of the Tudor DLLs contains a `bmkt`/`Prometheus` string.

So the firmware protocol is per SKU/PID, and the best evidence available is:

- **Positive:** same DLL line as a working ID, and *not* claimed by upstream
  `synaptics`.
- **Strongly positive:** Synaptics engineers *added and then removed* the PID
  from upstream `synaptics`. That happened to 00C9 (`eb1013c`, 2022) and 00E7
  (`3fb8860`, 2021), both of which now work with synatlsmoc, and to **00E9**
  (`0edae7b`, 2021).
- **Negative:** currently in upstream `synaptics`, especially when added by
  Synaptics staff (Aris Lin / Vincent Huang).

## Table

Line = `synaWudfBioUsbNNN.dll` product line. "syn" = upstream `synaptics`
id_table. "hwdb" = libfprint unsupported list. INF paths are relative to `OSD/`
unless they start with `HPD/`.

| PID | name string(s) | packages / DriverVer / line | synatlsmoc | syn | hwdb | verdict | evidence |
|---|---|---|---|---|---|---|---|
| 00C9 | Synaptics UWP WBDI | 111: 6.0.46, 6.0.49, 6.0.59, 6.0.62, 6.0.66 | enabled (tested) | removed 2022 (`eb1013c`) | no | already supported | `111/synaWudfBioUsbUwp.inf`, `downloads/msucat-6.0.66.1111/x/synaWudfBioUsbUwp.inf`, `HPD/SP141455/src/dchu_Driver/synaWudfBioUsbUwp.inf` |
| 00D8 | Synaptics FS7605 Touch Fingerprint Sensor with PurePrint(TM) | 110: 6.0.129, 6.0.130, 6.0.205 | enabled | no | no | already supported (v110 FRAME_ACQ flags differ, see FINDINGS 2026-10-11) | `110/synaWudfBioUsbUwpSvc.inf`, `downloads/msucat-6.0.205.1110/x/synaWudfBioUsbUwp.inf` |
| 00E7 | Synaptics UWP WBDI | 111: all | enabled (tested) | removed 2021 (`3fb8860`) | no | already supported | as 00C9 |
| 00FF | Synaptics UWP WBDI | 111: 6.0.49, 6.0.59, 6.0.62, 6.0.66 | enabled (tested) | no | no | already supported | `HPD/SP132990/dchu_Driver/synaWudfBioUsbUwp.inf`, `downloads/msucat-6.0.66.1111/x/synaWudfBioUsbUwp.inf` |
| **00D1** | Synaptics UWP WBDI | 111: all five builds | commented | no | no | **likely** | `111/synaWudfBioUsbUwp.inf`, `HPD/SP141455/…/synaWudfBioUsbUwp.inf`, `downloads/msucat-6.0.66.1111/x/synaWudfBioUsbUwp.inf` |
| **0169** | Synaptics UWP WBDI | 111: 6.0.62, 6.0.66 | commented | no | no | **likely** | `HPD/SP148234/dchu_Driver/synaWudfBioUsbUwp.inf`, `downloads/msucat-6.0.66.1111/x/synaWudfBioUsbUwp.inf` |
| **00E9** | Synaptics FS7606 Touch Fingerprint Sensor with PurePrint(TM) | 110: 6.0.129, 6.0.130, 6.0.205 | no | removed 2021 (`0edae7b`) | **yes** | **likely** (same line as 00D8; upstream dropped it like 00C9/00E7) | `110/synaWudfBioUsbUwpSvc.inf`, `LFP/libfprint/fprint-list-udev-hwdb.c:76` |
| 0124 | Synaptics UWP WBDI | 111: 6.0.59, 6.0.62, 6.0.66 | commented | **yes** (`c64fa9c`, 2024, non-Synaptics contributor) | no | conflict, test first | `HPD/SP141455/…/synaWudfBioUsbUwp.inf`, `LFP/libfprint/drivers/synaptics/synaptics.c:49` |
| 016C | — (no local INF lists it) | none found | **enabled** | **yes** (`42d1011`, 2024) | no | conflict: no Windows evidence for synatlsmoc | `LFP/libfprint/drivers/synatlsmoc/synatlsmoc.c:119`, `synaptics.c:54`, `LFP/data/autosuspend.hwdb:264` |
| 00C0 | Synaptics FS7614 Touch Fingerprint Sensor with PurePrint(TM) | 110: all three | no | no | no | possibly | `110/synaWudfBioUsbUwpSvc.inf`, `downloads/msucat-6.0.205.1110/x/synaWudfBioUsbUwp.inf` |
| 0109, 010A | Synaptics FS7606 … | 110: 6.0.205 only (2025) | no | no | no | possibly (siblings 0103-0108 are BMKT upstream) | `downloads/msucat-6.0.205.1110/x/synaWudfBioUsbUwp.inf` |
| 00FB | Synaptics UWP WBDI | 154: 6.0.5; 136: 6.0.69 | no | no | no | possibly (v136 IPT provisioning; fw 10.2/10.10 possible) | `downloads/msucat-6.0.5.1154/x/synaWudfBioUsbUwp.inf`, `downloads/msucat-6.0.69.1136/x/synaWudfBioUsbUwp.inf` |
| 016D | Synaptics UWP WBDI | 136: 6.0.69 (2026) | no | no | no | possibly (as 00FB) | `downloads/msucat-6.0.69.1136/x/synaWudfBioUsbUwp.inf` |
| 019F, 01A4 | Synaptics UWP WBDI | 171: 6.0.12 (2026, Synaptics SDCP layer) | no | no | no | possibly (newest line, SDCP, fw 10.10 possible) | `downloads/msucat-6.0.12.1171/x/synaWudfBioUsbUwp.inf` |
| 00CA | Synaptics UWP WBDI | 117: 6.0.7 (2018) | no | no | no | possibly (old line, 10.1 keys only) | `downloads/msucat-6.0.7.1117/x/synaWudfBioUsbUwp.inf` |
| 00EB | Synaptics UWP WBDI | 128: 6.0.2 (2019) | no | no | no | possibly (as 00CA) | `downloads/msucat-6.0.2.1128/x/synaWudfBioUsbUwp.inf` |
| 00E4 | Synaptics UWP WBDI | 127: 6.0.6 (2020) | no | no | yes | possibly | `127/synaWudfBioUsbUwp.inf`, `fprint-list-udev-hwdb.c:75` |
| 00FD | Synaptics UWP WBDI | 139: 6.0.503 (2021) | no | no | yes | possibly | `139/synaWudfBioUsbUwp.inf`, `fprint-list-udev-hwdb.c:77` |
| 00C4, 00DF, 00F0 | Synaptics FS7605 … | 110 | no | yes | no | unlikely (BMKT upstream) | `110/synaWudfBioUsbUwpSvc.inf`, `synaptics.c:36-39` |
| 0103, 0104, 0106 | Synaptics FS7606 … | 110 | no | yes | no | unlikely (BMKT upstream) | as above, `synaptics.c:43-45` |
| 0107, 0108 | Synaptics FS7606 … | 110: 6.0.205 | no | yes (`09ec6e6`) | no | unlikely | `downloads/msucat-6.0.205.1110/x/synaWudfBioUsbUwp.inf` |
| 00BD, 00C2, 0123 | Synaptics UWP WBDI | 105: 6.0.73 | no | yes | no | unlikely | `downloads/msucat-6.0.73.1105/x/synaWudfBioUsbUwp.inf` |
| 00F9, 00FC | Synaptics UWP WBDI | 154: 6.0.5; 136: 6.0.69 | no | yes | no | unlikely | `downloads/msucat-6.0.69.1136/x/synaWudfBioUsbUwp.inf` |
| 0126, 0129 | Synaptics UWP WBDI | 136: 6.0.69 | no | yes | no | unlikely | as above |
| 0173 | Synaptics UWP WBDI | 164: 6.1.13 | no | yes | no | unlikely | `downloads/msucat-6.1.13.1164/x/synaWudfBioUsbUwp.inf` |
| 019D | Synaptics UWP WBDI | 167: 6.0.19 | no | yes | no | unlikely | `downloads/msucat-6.0.19.1167/x/synaWudfBioUsbUwp.inf` |
| 00BE | Synaptics UWP WBDI SGX | 107-SGX: 6.0.48 (`synaWudfBioUsbSGX107.dll`) | no | no | yes | unlikely (SGX, libfprint keys absent) | `107/synaWudfBioUsbUwpSgx.inf` |
| 00BB, 00D2, 00F4 | Synaptics WBDI Fingerprint Reader - USB 102(SGX) | 102-SGX: 5.5.16, 5.5.34 (`synaWudfBioUSB102SGX.dll`) | no | no | 00BB yes | unlikely (5.x usdk5 SGX) | `102/synaWudfBioUsbHPSGXProd.inf`, `102_2/synaWudfBioUsbHPSGXProd.inf` |
| 00DC | Synaptics WBDI Fingerprint Reader - USB 124 | 124: 5.5.3 (Acer) | no | no | yes | unlikely (5.x usdk5, fw 6.x keys) | `124/synaWudfBioUsbAcerSecurePadProd.inf` |
| 009B | Synaptics WBDI Fingerprint Reader - USB 086 | 086: 5.5.5 (MSI, `synaWudfBioUsb.dll`) | no | no | yes | unlikely (5.x usdk5) | `fp_MSISecurePad-086 _v5_5_5_1086_x64_inf_5.5.5.1086_0x3ca86890/synaWudfBioUsbMSISecurePadProd.inf` |

Upstream `synaptics` also claims 00C6, 0100, 015F, 0168 and 0174, which no
local INF lists.

## Recommendations

Add or uncomment in `id_table`, in order of confidence:

1. **00D1** (uncomment). Every v111 build lists it next to the three tested
   IDs. It isn't claimed by any other driver.
2. **0169** (uncomment). Listed by v111 6.0.62/6.0.66 next to the tested
   IDs. Not claimed elsewhere. The project README already lists it.
3. **00E9** (add). Same v110 DLL as the working 00D8. Synaptics removed it
   from the BMKT driver (`0edae7b`), as they did with 00C9 and 00E7, which
   synatlsmoc now drives. When adding it, also remove it from
   `allowlist_id_table` (`fprint-list-udev-hwdb.c:76`). Otherwise
   `fprint-list-udev-hwdb` warns "implemented by driver"
   (`fprint-list-udev-hwdb.c:206-210`). Use the v110 FRAME_ACQ flags (see
   FINDINGS 2026-10-11).
4. Worth adding only behind testing: 00C0, 0109, 010A (v110). They belong to
   the 00D8 line and nobody else claims them, but their FS7605/FS7606
   siblings are BMKT devices.

For any v136/v105/v154/v164/v167/v171-line device (00FB, 016D, 019F, 01A4),
expect:

- firmware 10.2 or 10.10, which the exact-match check at `synatlsmoc.c:195-212`
  rejects; and
- for 10.10 with keyflag, a sensor key that libfprint lacks (x = `74f828…`,
  e.g. `synaWudfBioUsb110.dll` 6.0.205.1110 file offset 0xf14df).

Accepting 10.2 and 10.10 (non-kf) with the existing keys is what Windows does.
v136 also sends IPT provisioning (BOOTLDR_PATCH + PROVISION). See FINDINGS
2026-10-10.

### Be careful with

- **016C.** It is enabled in synatlsmoc, but upstream `synaptics` claims it
  too, and no local Windows INF lists it. Neither driver has `usb_discover`,
  so both score 50. The first registered driver wins (`fp-context.c:225-241`),
  and `synaptics` comes before `synatlsmoc` in `meson.build:135-136`. The
  synatlsmoc entry is therefore dead unless `synaptics` is disabled. The hwdb
  generator also files 016C under `synaptics` only (`autosuspend.hwdb:264`
  vs `272-275`). Either drop it or confirm with a device that it really speaks
  TLS/MiS.
- **0124.** It is in v111's INF, but upstream `synaptics` claims it
  (`c64fa9c`, 2024, a community contributor, not Synaptics). Enabling it has
  the same driver-order problem as 016C. Keep it commented until someone
  reports a GET_VERSION from it.
- **00E9, 00E4, 00FD.** These are on libfprint's unsupported list. Remove
  them from it when adding them, as described for 00E9 above.
- **Every other ID in a Tudor INF that upstream `synaptics` claims** (00BD,
  00C2, 00C4, 00DF, 00F0, 00F9, 00FC, 0103, 0104, 0106-0108, 0123, 0126, 0129,
  0173, 019D): don't add them. The shared Windows DLL is not evidence for
  them.
- **SGX / 5.x IDs** (009B, 00BB, 00BE, 00D2, 00DC, 00F4): different DLL
  family and key tables. Don't add them.
