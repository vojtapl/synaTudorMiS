# Sensor status words and VCS_RESULT codes

Extracted 2026-10-10. Nothing here has been verified yet.

## How it works

Every reply from the sensor starts with a u16 **status word**.
`tudorSecureBioConnect` (`synaWudfBioUsb111.dll @ 0x1800866d0`) handles it like
this:

- **`0x48c`**: the command is sent again, up to 3 tries. libfprint calls this
  `UNKNOWN_RESPONSE_ON_WHICH_SEND_AGAIN`.
- **Any other status**: converted to a host-side `VCS_RESULT_*` code by
  `fwReplyConvertToErrorCode`:
  - v111: `synaWudfBioUsb111.dll @ 0x180087f20`, named by the user
  - v136: `synaWudfBioUsb136.dll @ 0x1800a0ad0`

The names come from the table used by `result_code_to_str`
(`synaWudfBioUsb136.dll @ 0x1800d4c00`; table at `0x1801e37b0`, entries are
`{u32 code; u32 pad; char *name}`).

- The table has 71 names, and no build in the DLL survey has a `VCS_RESULT_*`
  name outside it.
- The unnamed codes `0xdc`, `0xdd`, `0xdf`, `0xe0` and `0xe1` come only from the
  status converter. They have no name in any build.
- In v111, `sendCmdFrameAcq` retries on `0xdf` (status `0x6ea`) with a 100 ms
  sleep. That is the "frame acquire busy" case.

## Sensor status word → VCS_RESULT

| status    | VCS_RESULT    | name                                   | note                                         |
| --------- | ------------- | -------------------------------------- | -------------------------------------------- |
| `0x000`   | `0x0` (0)     | VCS_RESULT_OK                          |                                              |
| `0x315`   | `0xd3` (211)  | VCS_RESULT_SENSOR_TLS_INTERNAL_FAILURE | v136+                                        |
| `0x401`   | `0xd1` (209)  | VCS_RESULT_SENSOR_BAD_CMD              |                                              |
| `0x403`   | `0x76` (118)  | VCS_RESULT_GEN_OBJECT_DOESNT_EXIST     |                                              |
| `0x404`   | `0x68` (104)  | VCS_RESULT_GEN_OPERATION_DENIED        |                                              |
| `0x405`   | `0x6f` (111)  | VCS_RESULT_GEN_BAD_PARAM               |                                              |
| `0x406`   | `0x6f` (111)  | VCS_RESULT_GEN_BAD_PARAM               |                                              |
| `0x412`   | `0x0` (0)     | VCS_RESULT_OK                          |                                              |
| `0x509`   | `0x12e` (302) | VCS_RESULT_MATCHER_MATCH_FAILED        |                                              |
| `0x5b6`   | `0xda` (218)  | VCS_RESULT_SENSOR_FRAME_NOT_READY      |                                              |
| `0x5cb`   | `0xdd` (221)  | _(unnamed)_                            |                                              |
| `0x5cc`   | `0x0` (0)     | VCS_RESULT_OK                          |                                              |
| `0x680`   | `0x1f5` (501) | VCS_RESULT_DB_FULL                     |                                              |
| `0x683`   | `0x76` (118)  | VCS_RESULT_GEN_OBJECT_DOESNT_EXIST     |                                              |
| `0x689`   | `0x68` (104)  | VCS_RESULT_GEN_OPERATION_DENIED        | v136+                                        |
| `0x6e0`   | `0xdc` (220)  | _(unnamed)_                            |                                              |
| `0x6ea`   | `0xdf` (223)  | _(unnamed)_                            |                                              |
| `0x70d`   | `0xe0` (224)  | _(unnamed)_                            | v136+                                        |
| `0x70e`   | `0xe1` (225)  | _(unnamed)_                            | v136+                                        |
| `0x48c`   | —             | (send again, up to 3×)                 | handled before conversion                    |
| any other | `0xca` (202)  | VCS_RESULT_SENSOR_MALFUNCTIONED        | logged "FW command reply failed with status" |

## All VCS_RESULT codes (v136 table; v111 has the same name strings)

| dec | hex     | name                                         |
| --- | ------- | -------------------------------------------- |
| 0   | `0x0`   | VCS_RESULT_OK                                |
| 100 | `0x64`  | VCS_RESULT_GEN_BASE                          |
| 101 | `0x65`  | VCS_RESULT_GEN_CORE_NOT_INITIALIZED          |
| 102 | `0x66`  | VCS_RESULT_GEN_BUSY                          |
| 103 | `0x67`  | VCS_RESULT_GEN_OPERATION_CANCELED            |
| 104 | `0x68`  | VCS_RESULT_GEN_OPERATION_DENIED              |
| 105 | `0x69`  | VCS_RESULT_GEN_ALREADY_ENROLLED              |
| 106 | `0x6a`  | VCS_RESULT_GEN_AUTHENTICATION_REQUIRED       |
| 107 | `0x6b`  | VCS_RESULT_GEN_NO_MATCH                      |
| 108 | `0x6c`  | VCS_RESULT_GEN_FINGER_NOT_ENROLLED           |
| 109 | `0x6d`  | VCS_RESULT_GEN_SIGNATURE_VERIFICATION_FAILED |
| 110 | `0x6e`  | VCS_RESULT_GEN_INVALID                       |
| 111 | `0x6f`  | VCS_RESULT_GEN_BAD_PARAM                     |
| 112 | `0x70`  | VCS_RESULT_GEN_NULL_POINTER                  |
| 113 | `0x71`  | VCS_RESULT_GEN_NOT_IMPLEMENTED               |
| 114 | `0x72`  | VCS_RESULT_GEN_UNEXPECTED_FORMAT             |
| 115 | `0x73`  | VCS_RESULT_GEN_NO_MORE_ENTRIES               |
| 116 | `0x74`  | VCS_RESULT_GEN_BUFFER_TOO_SMALL              |
| 117 | `0x75`  | VCS_RESULT_GEN_TIMEOUT                       |
| 118 | `0x76`  | VCS_RESULT_GEN_OBJECT_DOESNT_EXIST           |
| 119 | `0x77`  | VCS_RESULT_GEN_ERROR                         |
| 200 | `0xc8`  | VCS_RESULT_SENSOR_BASE                       |
| 201 | `0xc9`  | VCS_RESULT_SENSOR_RESET                      |
| 202 | `0xca`  | VCS_RESULT_SENSOR_MALFUNCTIONED              |
| 203 | `0xcb`  | VCS_RESULT_SENSOR_UNAVAILABLE                |
| 204 | `0xcc`  | VCS_RESULT_SENSOR_NEED_TO_RESET_OWNER        |
| 205 | `0xcd`  | VCS_RESULT_SENSOR_IN_AUTONOMOUS_MODE         |
| 206 | `0xce`  | VCS_RESULT_SENSOR_NOT_READY_FOR_USE          |
| 207 | `0xcf`  | VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP       |
| 208 | `0xd0`  | VCS_RESULT_SENSOR_FW_EXT_PROGRAM_FAILED      |
| 209 | `0xd1`  | VCS_RESULT_SENSOR_BAD_CMD                    |
| 210 | `0xd2`  | VCS_RESULT_SENSOR_DRV_OPEN_FAILED            |
| 211 | `0xd3`  | VCS_RESULT_SENSOR_TLS_INTERNAL_FAILURE       |
| 212 | `0xd4`  | VCS_RESULT_SENSOR_PARTITION_NOT_OPENED       |
| 213 | `0xd5`  | VCS_RESULT_SENSOR_PARTITION_IS_FULL          |
| 214 | `0xd6`  | VCS_RESULT_SENSOR_CALIBRATION_FAIL           |
| 215 | `0xd7`  | VCS_RESULT_SENSOR_CALIBRATION_RETRY          |
| 216 | `0xd8`  | VCS_RESULT_SENSOR_INVALID_BASELINE           |
| 217 | `0xd9`  | VCS_RESULT_SENSOR_CAPTURE_RESET              |
| 218 | `0xda`  | VCS_RESULT_SENSOR_FRAME_NOT_READY            |
| 300 | `0x12c` | VCS_RESULT_MATCHER_BASE                      |
| 301 | `0x12d` | VCS_RESULT_MATCHER_OPEN_FAILED               |
| 302 | `0x12e` | VCS_RESULT_MATCHER_MATCH_FAILED              |
| 303 | `0x12f` | VCS_RESULT_MATCHER_EXTRACT_FAILED            |
| 304 | `0x130` | VCS_RESULT_MATCHER_ENROLL_FAILED             |
| 305 | `0x131` | VCS_RESULT_MATCHER_ADD_IMAGE_FAILED          |
| 306 | `0x132` | VCS_RESULT_MATCHER_FP_AREA_IMAGE_DISCARDED   |
| 307 | `0x133` | VCS_RESULT_MATCHER_SET_PARAMETER_FAILED      |
| 308 | `0x134` | VCS_RESULT_MATCHER_CLOSE_FAILED              |
| 400 | `0x190` | VCS_RESULT_IMGPROC_BASE                      |
| 401 | `0x191` | VCS_RESULT_IMGPROC_COMPLETE                  |
| 402 | `0x192` | VCS_RESULT_IMGPROC_IN_PROGRESS               |
| 403 | `0x193` | VCS_RESULT_IMGPROC_FINGER_SETTLED            |
| 404 | `0x194` | VCS_RESULT_IMGPROC_NO_IMAGE_CAPTURED         |
| 405 | `0x195` | VCS_RESULT_IMGPROC_FINGER_REMOVED            |
| 406 | `0x196` | VCS_RESULT_IMGPROC_FINGER_ON_SENSOR          |
| 407 | `0x197` | VCS_RESULT_IMGPROC_FINGER_DETECTED           |
| 408 | `0x198` | VCS_RESULT_IMGPROC_ACQUISITION_NO_IMAGE      |
| 500 | `0x1f4` | VCS_RESULT_DB_BASE                           |
| 501 | `0x1f5` | VCS_RESULT_DB_FULL                           |
| 502 | `0x1f6` | VCS_RESULT_DB_EMPTY                          |
| 600 | `0x258` | VCS_RESULT_SYS_BASE                          |
| 601 | `0x259` | VCS_RESULT_SYS_CALL_FAILED                   |
| 602 | `0x25a` | VCS_RESULT_SYS_OUT_OF_MEMORY                 |
| 603 | `0x25b` | VCS_RESULT_SYS_FILE_OPEN_FAILED              |
| 604 | `0x25c` | VCS_RESULT_SYS_FILE_WRITE_FAILED             |
| 605 | `0x25d` | VCS_RESULT_SYS_FILE_READ_FAILED              |
| 700 | `0x2bc` | VCS_RESULT_VRC_BASE                          |
| 701 | `0x2bd` | VCS_RESULT_VRC_INVALID_OP_ID                 |
| 702 | `0x2be` | VCS_RESULT_VRC_BUFER_TO_BIG                  |
| 703 | `0x2bf` | VCS_RESULT_VRC_INVALID_PARAM                 |
