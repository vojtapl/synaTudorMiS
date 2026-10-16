# Guidelines for AI agents (and humans using them)

These rules apply to commits, issues and pull requests made with the help of an
AI agent, in this repository and in the libfprint fork that carries the driver.
Read them before changing anything.

## The repositories

| repository                 | what it is                                                                                                | where changes go                                                            |
| -------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `synaTudorMiS` (this repo) | reverse-engineering notes (`rev/`), the Python lab driver (`pydrv/`), driver packages and Ghidra material | PRs to <https://github.com/vojtapl/synaTudorMiS>                            |
| libfprint fork             | the `synatlsmoc` driver (`libfprint/drivers/synatlsmoc/`)                                                 | PRs to <https://github.com/vojtapl/libfprint>, not to upstream libfprint    |
| fprintd patch              | `libfprint/fprintd-load-store-persistent-data-from-device.patch`, needed to keep pairing data             | edit it in this repo; regenerate it from a real fprintd tree, never by hand |

Upstream libfprint (<https://gitlab.freedesktop.org/libfprint/libfprint>) has
its own rules in the fork's `HACKING.md`. Read them, especially the license
clarification: no proprietary code goes into libfprint.

## pydrv is a lab tool

- `pydrv/` is a **prototype for experiments**, not a driver for real use.
  - It prompts interactively, prints protocol data and has no hardening.
  - Don't package it, build login or authentication on it, or recommend it to
    end users. They need the libfprint driver.
- pydrv behaviour is **not evidence**. Don't port something from pydrv to
  libfprint because "pydrv does it". Port it because the Windows driver does it
  (see below), or because a hardware test showed it.
- Lab-only commands (e.g. `led`, `gpio_write_test`) may send raw commands. Keep
  that kind of thing out of libfprint.

## The Windows driver is the specification

`synatlsmoc` reimplements what the Windows driver sends. Where the two differ,
the Windows driver wins; this includes its non-standard TLS dialect. See "Design
principle" in `libfprint/DRIVER_ISSUES.md`.

- **Behaviour changes need evidence:** a Windows driver reference (below) or a
  hardware test on a named device. "This is what the RFC/spec says" or "this
  looked cleaner" is not enough for the protocol code.
- **Say how you deviate:** if you change the order or timing compared with
  Windows on purpose, say so in the commit and in `rev/FINDINGS.md`, with the
  reason. Example: the LED "waiting" event sent after FRAME_ACQ instead of
  before.

## Reporting anything learned from a Windows DLL

Every claim derived from a Windows binary must say exactly where it came from.
Addresses and behaviour differ between driver builds.

1. **Name the binary and its build:**
   - file name, e.g. `synaWudfBioUsb123.dll`;
   - file version, e.g. `6.0.25.1123`;
   - SHA-256 if you have it;
   - the package it came from and where to download it (table below).
2. **Give addresses** as `synaWudfBioUsb111.dll @ 0x180012340`, i.e. image base
   `0x180000000`, not file offsets. If you give a file offset, say so.
3. **Say how sure you are:**
   - `verified`: hardware test or an independent check, e.g. byte comparison;
   - `decompilation` / `disassembly`: read from the code;
   - `inferred`: guessed from names, sizes or strings.

   Decompiler output is wrong now and then; for anything that matters, check the
   disassembly.
4. **Write it down** in `rev/FINDINGS.md`, newest entry first, using the format
   at the top of that file. Correct older entries and notes when you prove them
   wrong; say what changed and when.
5. **Names:**
   - Use Synaptics' original names where the DLL has them (log strings, name
     tables).
   - Mark everything you named yourself as non-original, e.g.
     `/* non-original name */`.

Known driver builds and where to get them:

| build (DLL suffix)                     | version(s)                           | sensors (examples)                | source                                                                                                                                                                      |
| -------------------------------------- | ------------------------------------ | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 104                                    | —                                    | original synaTudor reference      | Lenovo package `r17fq02w.exe`: <https://download.lenovo.com/pccbbs/mobiles/r17fq02w.exe> (see `rev/README.md`)                                                              |
| 111                                    | 6.0.49 / 6.0.59 / 6.0.62 / 6.0.66    | 06CB:00C9, 00D1, 00E7, 00FF, 0169 | HP SoftPaqs SP132990 (6.0.49), **SP141455 (6.0.59, the build in the Ghidra project)**, SP148234 (6.0.62). The same driver is in the Microsoft Update Catalog (6.0.66.1111). |
| 110                                    | 6.0.129 / 6.0.130 / 6.0.205          | 06CB:00D8, 00E9                   | Microsoft Update Catalog (`6.0.205.1110`)                                                                                                                                   |
| 123                                    | 6.0.25.1123                          | 047D:8054, 06CB:00D6              | Kensington VeriMark IT driver package (`synaWudfBioUsbUwpOne.inf`)                                                                                                          |
| 105, 117, 128, 136, 154, 164, 167, 171 | see `rev/notes/dll-survey/table.txt` | newer and older lines             | Microsoft Update Catalog, searching for the version, e.g. `6.0.69.1136`                                                                                                     |

- Microsoft Update Catalog: <https://www.catalog.update.microsoft.com/>.
- HP SoftPaqs follow the pattern
  `https://ftp.hp.com/pub/softpaq/spNNN001-NNN500/spNNNNNN.exe`, e.g.
  `sp141001-141500/sp141455.exe`. Check that the link still works.
- `rev/notes/dll-survey/` lists every surveyed build with SHA-256, version and
  PDB path. `rev/notes/usb-id-survey.md` maps USB IDs to builds.

## What must not be committed

- Windows driver binaries, firmware blobs, or large chunks of decompiled code.
  Small protocol constants recovered from a DLL (e.g. the LED_EX2 profile
  table), with their provenance, are fine.
- Real pairing data, private keys, TLS secrets, or debug logs that contain them.
  Builds with `DEBUG` log keys and certificates; scrub logs before attaching
  them.
- Personal data in logs: user names, Windows SIDs, serial numbers.
- Local files: `.gitignore` changes for your own setup, scratch files, build
  directories.

## Hardware claims

- Say what you tested, on which device (VID:PID, firmware version from
  GET_VERSION, laptop model) and what you didn't test. Never write "works" for
  something that only compiled.
- A new USB ID goes into `id_table` only with a log from the device, or with
  Windows INF evidence plus a note that it is untested. Watch out for IDs that
  upstream's `synaptics` (BMKT) driver claims: the first registered driver wins.
- If you change `id_table`:
  - regenerate `data/autosuspend.hwdb` with `ninja -C <build> sync-udev-hwdb`;
  - remove the ID from the unsupported list in
    `libfprint/fprint-list-udev-hwdb.c`.

## Commits and pull requests

- One logical change per commit. Keep messages short, in the existing style:
  `synatlsmoc: <what changed>`, e.g.
  `synatlsmoc: report full storage as
  DATA_FULL`.
- **Before proposing a libfprint change:**
  - build with no new warnings;
  - run `meson test` (at least `udev-hwdb` and the unit tests);
  - for memory changes, run valgrind on enroll, verify and list.
- **Don't open PRs or push on your own.** A human reviews every change, and runs
  the hardware test, before it is submitted.
- **Say it was AI-assisted** in the PR description, list what was verified and
  how, and keep unverified parts clearly marked.
- **Track open work** in `libfprint/DRIVER_ISSUES.md`: add items there, tick
  them off when done, and say what still needs a hardware test.

## Ghidra (only with access to the maintainer's project)

If you work in the maintainer's Ghidra project (via the ReVa MCP server), follow
the marking rules in `CLAUDE.md`:

- `ai_` name prefix, `[AI]` comments, the `AI` tag and the `/AI` category;
- never overwrite names the user wrote;
- no scripts or check-ins unless asked.

Otherwise, just report addresses as described above.
