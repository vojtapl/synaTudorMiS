# DLL string survey (2026-10-10)

Output of the AI-run string survey of every `synaWudfBioUsb*.dll` and
`synaFpAdapter*.dll` available locally. That covers
`~/Projects/done/other synaptics drivers/` and the newer builds downloaded
from the Microsoft Update Catalog and HP into its `downloads/` folder. The
survey only read strings: nothing was run and nothing was imported into
Ghidra.

| file | contents |
|---|---|
| `table.txt` | one row per build: version, architecture, string counts, keyword counts |
| `survey.json` | the full per-file records (82 files): paths, sha256, version, PDB path |
| `q2.txt`, `q2_new.txt` | hits for provisioning, PSK, ownership, security mode, FRAME_ACQ and capture flags, each with the files it was found in |
| `new_builds_report.txt` | strings in the downloaded builds that no earlier build has, grouped by topic; also the 6.0.66 vs 6.0.59 (`111`) diff |
| `vcsfw_names.json` | every `VCSFW_*` name, with the builds it appears in |
| `survey2.py`, `newdiff.py` | the scripts used |

Builds suggested for loading into Ghidra:

1. `136` 6.0.69 (IPT provisioning, PSK, basic/advanced security, WOF_AL0 capture flags)
2. `139` 6.0.24 (named host-side frame-acquire and capture path)
3. `110` 6.0.205 (host partition, GWK seed / machine GUID, reset ownership)
4. `171` 6.0.12 (Synaptics SDCP layer)
5. `164` 6.1.13 (pairing-data encryption with system crypto, opinfo tags)
