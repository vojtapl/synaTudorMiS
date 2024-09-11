# How I made these breakpoints:

1. find memory offset in Ghidra - leftest number in listing window
2. find offset of entry point - `FxDriverEntryUm` (as the `synawudfbiousb111.dll` does not advertise any useful functions), which is 180024420
3. find the DIFFERENCE in **hex**: DIFFERENCE=(ADDR - 0x180024420)
4. add breakpoint with: `bp synawudfbiousb111!FxDriverEntryUm+DIFFERENCE` in the `Command` window
