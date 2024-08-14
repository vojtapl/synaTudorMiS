/*
 * TODO: header
 */

typedef enum {
   SYNAPTICS_CMD_SEND_PENDING = 0,
   SYNAPTICS_CMD_GET_RESP,
   SYNAPTICS_CMD_WAIT_INTERRUPT,
   SYNAPTICS_CMD_SEND_ASYNC,
   SYNAPTICS_CMD_RESTART,
   SYNAPTICS_CMD_SUSPENDED,
   SYNAPTICS_CMD_RESUME,
   SYNAPTICS_CMD_NUM_STATES,
} SynapticsCmdState;

typedef enum {
   CMD_STATE_SEND_PENDING = 0,
   CMD_STATE_GET_RESP,
   CMD_STATE_WAIT_INTERRUPT,
   CMD_STATE_RESTART,
   CMD_STATE_SUSPENDED,
   CMD_STATE_RESUME,
   CMD_NUM_STATES,
} FpCommState;

// Task SSMs ------------------------------------------------------------------

typedef enum {
   INIT_SEND_GET_VERSION = 0,
   INIT_GET_BOOTLOADER_STATE,
   INIT_NUM_STATES,
} FpInitState;

typedef enum {
   CLOSE_NUM_STATES,
} FpCloseState;

typedef enum {
   ENROLL_NUM_STATES,
} FpEnrollState;

typedef enum {
   VERIFY_NUM_STATES,
} FpVerifyState;

typedef enum {
   IDENTIFY_STATE_CAPTURE_FRAME = 0,
   IDENTIFY_STATE_GET_IMAGE_QUALITY,
   IDENTIFY_STATE_CHECK_IMAGE_QUALITY,
   IDENTIFY_STATE_IDENTIFY_MATCH,
   IDENTIFY_NUM_STATES,
} FpIdentifyState;

typedef enum {
   CAPTURE_NUM_STATES,
} FpCaptureState;

typedef enum {
   LIST_NUM_STATES,
} FpListState;

typedef enum {
   DELETE_NUM_STATES,
} FpDeleteState;

typedef enum {
   CLEAR_STORAGE_NUM_STATES,
} FpClearStorageState;

typedef enum {
   CANCEL_NUM_STATES,
} FpCancelState;

typedef enum {
   SUSPEND_NUM_STATES,
} FpSuspendState;

typedef enum {
   RESUME_NUM_STATES,
} FpResumeState;
