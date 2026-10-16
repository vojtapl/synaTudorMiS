# synaTudorMiS

Linux (libfprint) driver for Synaptics Tudor fingerprint sensors, built by
reverse engineering the Windows driver (`synaWudfBioUsb*.dll`,
`synaFpAdapter*.dll`).

- `libfprint/` — the libfprint fork with the `synatlsmoc` driver
- `rev/` — reverse-engineering docs (`proto.txt`, `rev.txt`, IOCTL lists,
  `FINDINGS.md`) and Ghidra `.gzf` exports
- `HP drivers/`, `reverse engineering/` — Windows driver packages and WinDbg notes

## Reverse-engineering tools

Two MCP servers are available:

- **ReVa** (`http://localhost:8080/mcp/message`) — runs inside the user's Ghidra
  GUI against the user's real project, which already holds most of the RE work
  (renamed functions, types, comments). Prefer it for anything about the driver.
  It works only while Ghidra is running with the project open. If it is
  unreachable, ask the user to start Ghidra; don't fall back to guessing.
- **REA** (`rea`) — imports a fresh, throwaway copy of a binary each time and
  never sees the user's annotations. Use it only for one-off questions on
  binaries that aren't in the Ghidra project.

### Marking changes in the Ghidra project

Everything Claude writes into the Ghidra database must be recognizable as
unverified AI work:

- **Names** (functions, labels, globals, variables): prefix with `ai_`, e.g.
  `ai_parse_pairing_blob`. The user removes the prefix once they have verified it.
- **Comments**: start with `[AI]`.
- **Functions** Claude renamed, retyped or commented: add the function tag `AI`.
- **Data types / structs** Claude creates: put them in the `/AI` category.
- **Bookmarks**: category `AI`.
- **Never overwrite** a name, type or comment that the user wrote, i.e. anything
  without the markers above that isn't a Ghidra default (`FUN_`, `DAT_`,
  `LAB_`, `param_`, `local_`, ...). If you think one is wrong, say so in
  `rev/FINDINGS.md` and to the user instead.
- ReVa's `rename-variables` commits the decompiler's parameter list, which can
  replace user-named parameters in the listing with the decompiler's `param_N`.
  Compare the function signature before and after renaming, and restore any
  name that got clobbered.
- Don't run `run-script`, `write-script` or `edit-script`, and don't check
  programs in, unless the user asks.

### Notes

Record findings in `rev/FINDINGS.md` as you go (format at the top of that
file). Give addresses together with the program and driver version, e.g.
`synaWudfBioUsb111.dll @ 0x180012340`, because addresses differ between versions.
