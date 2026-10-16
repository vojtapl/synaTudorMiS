# `VCSFW_CMD_LED_EX2` default profiles

Target: `synaWudfBioUsb123.dll` (x64, SHA-256
`61497cb129b85b75a1df34c41e44d863506978575fdbe7cc7f098b4d378e4792`).

## Where the payload data comes from

The LED profiles are not supplied by Windows and are not obtained from
`synaFpAdapter123.dll`. They are a hard-coded 0x2e8-byte table in the Wudf
DLL at VA `0x1800cc8a0`.

During session initialization:

```c
FUN_18004eae0(session)
    -> FUN_180055990(session);       // vfmUtilLedInitialize

FUN_180055990(session) {
    *(uint32_t *)(session + 0x420) = 0;
    memcpy((void *)(session + 0xf8), (void *)0x1800cc8a0, 0x2e8);
}
```

The copied table is six records of 0x7c bytes. `FUN_180056740(session, i)`
selects record `i` at `session + 0xf8 + 0x7c*i`, then passes it through
`vfmDeviceLedConfigure` to `sendLedEx2Cmd` (`FUN_180082960`). A later
`vfmUtilSetLedEventsConfig` call can replace the session copy, but the values
below are the built-in defaults.

## Record layout used by `sendLedEx2Cmd`

Input record size is 0x7c:

```text
offset  size       meaning in host code
0x00    4          event duration/timeout, copied verbatim
0x04    6*0x14     six LED action records

action +0x00       2 bytes copied
action +0x02       2 bytes ignored
action +0x04       4 bytes copied
action +0x08       2 bytes copied, +0x0a..0x0b ignored
action +0x0c       2 bytes copied, +0x0e..0x0f ignored
action +0x10       2 bytes copied, +0x12..0x13 ignored
```

(Corrected 2026-10-16 from the disassembly at `0x180082ad6`..`0x180082c78`:
the inner loop copies two bytes per 32-bit slot. The earlier text said
+0x04..0x0f were copied whole and +0x10 ignored. For the built-in table it
makes no difference: every ignored byte is zero, and so is every +0x10 value.
A byte-for-byte simulation of all six records matches what synatlsmoc sends.)

The serialized command is 0x7d bytes:

```c
out[0] = 0x39;                         // VCSFW_CMD_LED_EX2
u32le(out + 1) = u32le(in + 0);
for (int i = 0; i != 6; ++i) {
    const uint8_t *a = in + 4 + 0x14*i;    // source action
    uint8_t *b = out + 5 + 0x14*i;         // serialized action
    memcpy(b + 0x00, a + 0x00, 2);
    memcpy(b + 0x04, a + 0x04, 4);
    memcpy(b + 0x08, a + 0x08, 2);
    memcpy(b + 0x0c, a + 0x0c, 2);
    memcpy(b + 0x10, a + 0x10, 2);
    // all other bytes remain zero
}
```

Thus the firmware sees a normalized 20-byte action record: the host's two
ignored fields are replaced with zero. The exact physical interpretation of
the action fields is not named in this DLL; their likely meanings must be
confirmed against firmware behavior or additional protocol documentation.

## Built-in records and when they are selected

The following values are decoded as little-endian. `field0` is the first
two-byte action field; `params` are the three copied 32-bit values at action
offsets `+0x04`, `+0x08`, and `+0x0c`. `x` means the complete action is zero.

| event index | table VA | outer duration | nonzero actions (`field0`; params) | observed use |
|---:|---:|---:|---|---|
| 0 | `0x1800cc8a0` | 0 ms | all six: `0x0000; 0x20000000,0,0` | idle/default/reset/settled state |
| 1 | `0x1800cc91c` | 160000 ms | actions 0–2: `0xffff; 0x20000505,0,0x00000505` | capture/enrollment waiting-for-finger state |
| 2 | `0x1800cc998` | 500 ms | action 0: `0x01f4; 0x20000507,0,0x00000505`; action 2: `0x01f4; 0x20000500,0,0` | enrollment sample accepted, and enrollment complete |
| 3 | `0x1800cca14` | 1000 ms | action 0: `0x01f4; 0x20000107,0x00000101,0`; action 2: `0x01f4; 0x20000100,0,0` | enrollment sample rejected, or add-image error |
| 4 | `0x1800cca90` | 500 ms | identical to event 2 | match success |
| 5 | `0x1800ccb0c` | 1000 ms | actions 0–3: `0x004b` with params respectively `0x20000107,0x00000101,0`; `0x20000001,0,0`; `0x20000101,0,0`; `0x20000001,0,0` | match failure |

The event-to-state labels are inferred from the callers of
`FUN_180056740`: event 0 is the normal baseline path; event 1 is used while
waiting for capture/finger input; event 2 is an accepted enrollment
sample (also sent when enrollment completes) and event 3 a rejected one
(corrected 2026-10-16; see `rev/FINDINGS.md`); events 4 and 5 are match success/failure.

`0xd1` is `VCS_RESULT_SENSOR_BAD_CMD`. `sendLedEx2Cmd` retries the same
`LED_EX2` command once after this result; it is a firmware rejection of the
command, not an LED profile selector.

