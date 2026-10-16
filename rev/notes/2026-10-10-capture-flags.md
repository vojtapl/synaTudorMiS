# Capture flags (`CAPTURE_FLAG_*`): v104 vs v111

Saved answer from 2026-10-10. The full evidence is in `rev/FINDINGS.md`, in the
entries "captureFlags bits, v104 vs v111" and "VCSFW_CMD_FRAME_ACQ (0x80)
request layout". Nothing here has been verified yet.

## Capture flag bits

| bit   | v104 (reads images)                                                                                                                              | v111 (matches on the sensor)                         |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| `0x1` | Together with `0x2`, selects the mode. The frame read fails with "The last frame is not received" if the frame doesn't have the last-frame flag. | Mode selection only                                  |
| `0x2` | Together with `0x1`, selects the mode. With trigger 1, the driver reports "finger detected" before the frame is ready.                           | Same                                                 |
| `0x4` | Run image post-processing on the PC                                                                                                              | Always set (7 and 15), but nothing reads it any more |
| `0x8` | Set for enroll, but the low-level layer ignores it, so it doesn't change what's sent                                                             | Enroll: acq flags `\|= 8`. Otherwise `\|= 0x1010`.   |

Bits above `0x3f` are rejected (`vfmCaptureStart`).

## What changed between versions

- **Same in both:** the purpose-to-flags chain (enroll → 15, verify/identify →
  7, 1 frame, trigger 1) and the whole FRAME_ACQ packet layout.
- **Changed:** only the acq flags field at bytes `[1..4]`.

| mode                            | v104 acq flags   | v111 acq flags                             |
| ------------------------------- | ---------------- | ------------------------------------------ |
| 1 (N frames)                    | `N == 0 ? 1 : 0` | `N == 0 ? 1 : 4`, then the enroll-bit rule |
| 2 (one frame, finger-triggered) | `0`              | `4`, then the enroll-bit rule              |
| 3 (open-ended / streaming?)     | `1`              | `1`, then the enroll-bit rule              |

The enroll-bit rule: `|= 8` for enroll, otherwise `|= 0x1010`.

- **So in v104, enroll and verify sent identical packets.** The difference
  between 12 and 4116 is new in later firmware.
- **Likely meaning of the acq flag bits:**
  - `0x1`: no frame count, open-ended
  - `0x4`: fixed frame count
  - `0x8` vs `0x1010`: what the on-sensor image is for (enroll vs match). This
    one is an inference, not something the code shows.

## Modes (the `1_2_3` argument of `sendCmdFrameAcq`)

Only mode 2 is used in v111. Modes 1 and 3 can't be reached: their only possible
caller, `vfmUtilFrameRead`, has no callers. FRAME_READ and FRAME_STREAM are
never called either.

- **Mode 1:** immediate raw/test capture of N frames, with no finger trigger.
- **Mode 2:** one frame, started by a finger.
- **Mode 3:** continuous or streaming capture, maybe navigation.

## For libfprint

```c
CAPTURE_FLAG_SINGLE_FRAME = 1 << 0 | 1 << 1, /* mode 2: one finger-triggered frame */
CAPTURE_FLAG_POSTPROCESS  = 1 << 2,          /* legacy; always set */
CAPTURE_FLAG_ENROLL_BIT   = 1 << 3,
CAPTURE_FLAG_AUTH   = 7,   /* acq flags 0x1014 */
CAPTURE_FLAG_ENROLL = 15,  /* acq flags 0x000c */
```

`send_frame_acquire` could compute the flags the way Windows does:
`4 | (flags & 8 ? 8 : 0x1010)`.

The comment in `synatlsmoc.h` says 0x00D8 needs AUTH set to 15. Windows itself
never sends anything but 12 or 4116, so that doesn't explain it. Things to
check:

- Whether 0x00D8 is happy when enroll sends 12 and verify sends 4116.
- Whether the original failure was really a retry/status problem. The
  uncommitted retry fixes may matter here.

Other `recv_frame_acquire` issues seen in the committed code:

- A retry always jumps to `ENROLL_SEND_FRAME_ACQUIRE`, which in verify is the
  wrong state.
- Identify hits `g_assert_not_reached()`.
- There is no 100 ms wait between retries.
