/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * Copyright (c) 2024 Francesco Circhetta, Vojtěch Pluskal
 *
 * some parts are based on work of Popax21 see:
 * https://github.com/Popax21/synaTudor/tree/rev
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <openssl/evp.h>

#include "fpi-device.h"

G_DECLARE_FINAL_TYPE (FpiDeviceSynaTlsMoc, fpi_device_synatlsmoc, FPI, DEVICE_SYNATLSMOC, FpDevice);

#define SYNATLSMOC_DRIVER_FULLNAME "Synaptics Tudor Match-In-Sensor"
#define SYNATLSMOC_ENROLL_STAGES 10

#define SYNAPTICS_VENDOR_ID 0x06cb

#define SYNATLSMOC_EP_CMD_OUT (0x1 | FPI_USB_ENDPOINT_OUT)
#define SYNATLSMOC_EP_RESP_IN (0x1 | FPI_USB_ENDPOINT_IN)
#define SYNATLSMOC_EP_INTERRUPT (0x3 | FPI_USB_ENDPOINT_IN)

#define REQUEST_TLS_SESSION_STATUS 0x14
#define REQUEST_DFT_WRITE 0x15

#define TLS_SESSION_STATUS_RESP_LEN 2

#define SYNATLSMOC_USB_CONTROL_TIMEOUT 2000
#define SYNATLSMOC_USB_SEND_TIMEOUT 2000
#define SYNATLSMOC_USB_RECV_TIMEOUT 2000
#define SYNATLSMOC_USB_INTERRUPT_TIMEOUT 60000

#define WRAP_RESPONSE_ADDITIONAL_SIZE 0x45

#define ADVANCED_SECURITY_MASK 0x1
#define KEY_FLAG_MASK 0x20
#define PROVISION_STATE_MASK 0xF
#define SENSOR_FW_REPLY_STATUS_HEADER_LEN 2

#define WINBIO_SID_SIZE 76
#define DB2_ID_SIZE 16

#define FRAME_ACQUIRE_NUM_RETRIES 3

#define IMAGE_QUALITY_THRESHOLD 50

/* known command IDs */
typedef enum
{
  VCSFW_CMD_GET_VERSION = 0x01,
  VCSFW_CMD_RESET = 0x05,
  VCSFW_CMD_PEEK = 0x07,
  VCSFW_CMD_POKE = 0x08,
  VCSFW_CMD_PROVISION = 0x0e,
  VCSFW_CMD_RESET_OWNERSHIP = 0x10,
  VCSFW_CMD_GET_STARTINFO = 0x19,
  VCSFW_CMD_LED_EX2 = 0x39,
  VCSFW_CMD_STORAGE_INFO_GET = 0x3e,
  VCSFW_CMD_STORAGE_PART_FORMAT = 0x3f,
  VCSFW_CMD_STORAGE_PART_READ = 0x40,
  VCSFW_CMD_STORAGE_PART_WRITE = 0x41,
  VCSFW_CMD_TLS_DATA = 0x44, /* non-original name */
  VCSFW_CMD_DB_OBJECT_CREATE = 0x47,
  VCSFW_CMD_TAKE_OWNERSHIP_EX2 = 0x4f,
  VCSFW_CMD_GET_CERTIFICATE_EX = 0x50,
  VCSFW_CMD_TIDLE_SET = 0x57,
  VCSFW_CMD_BOOTLDR_PATCH = 0x7d,
  VCSFW_CMD_FRAME_READ = 0x7f,
  VCSFW_CMD_FRAME_ACQ = 0x80,
  VCSFW_CMD_FRAME_FINISH = 0x81,
  VCSFW_CMD_FRAME_STATE_GET = 0x82,
  VCSFW_CMD_EVENT_CONFIG = 0x86,
  VCSFW_CMD_EVENT_READ = 0x87,
  VCSFW_CMD_FRAME_STREAM = 0x8b,
  VCSFW_CMD_IOTA_FIND = 0x8e,
  VCSFW_CMD_PAIR = 0x93,
  VCSFW_CMD_ENROLL = 0x96,
  VCSFW_CMD_IDENTIFY_MATCH = 0x99,    /* non-original name */
  VCSFW_CMD_GET_IMAGE_METRICS = 0x9d, /* non-original name */
  VCSFW_CMD_DB2_GET_DB_INFO = 0x9e,
  VCSFW_CMD_DB2_GET_OBJECT_LIST = 0x9f,
  VCSFW_CMD_DB2_GET_OBJECT_INFO = 0xa0,
  VCSFW_CMD_DB2_GET_OBJECT_DATA = 0xa1,
  VCSFW_CMD_DB2_WRITE_OBJECT = 0xa2,
  VCSFW_CMD_DB2_DELETE_OBJECT = 0xa3,
  VCSFW_CMD_DB2_CLEANUP = 0xa4,
  VCSFW_CMD_DB2_FORMAT = 0xa5,
  /* ? 0xa6 */
  VCSFW_CMD_RESET_SBL_MODE = 0xaa, /* non-original name */
  VCSFW_CMD_EXTSIG = 0xab,
  VCSFW_CMD_SSO = 0xac,
  VCSFW_CMD_OPINFO_GET = 0xae,
  VCSFW_CMD_HW_INFO_GET = 0xaf,
  VCSFW_CMD_GET_VERSION2 = 0xb4,
  VCSFW_CMD_EXT_COMMAND = 0xe5,
} VCSFW_CMD;

typedef enum
{
  VCS_RESULT_OK_1 = 0x000,
  LAST_TLS_SESSION_NOT_CLOSED = 0x315,
  VCS_RESULT_SENSOR_BAD_CMD = 0x401,
  VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_1 = 0x403,
  VCS_RESULT_GEN_OPERATION_DENIED_1 = 0x404,
  VCS_RESULT_GEN_BAD_PARAM_1 = 0x405,
  VCS_RESULT_GEN_BAD_PARAM_2 = 0x406,
  VCS_RESULT_GEN_BAD_PARAM_3 = 0x407,
  VCS_RESULT_OK_2 = 0x412,
  UNKNOWN_RESPONSE_ON_WHICH_SEND_AGAIN = 0x48c,
  VCS_RESULT_MATCHER_MATCH_FAILED = 0x509,
  VCS_RESULT_SENSOR_FRAME_NOT_READY = 0x5B6,
  VCS_RESULT_OK_3 = 0x5CC,
  VCS_RESULT_DB_FULL = 0x680,
  VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 = 0x683,
  VCS_RESULT_GEN_OPERATION_DENIED_2 = 0x689,
  RESPONSE_PROCESSING_FRAME = 0x6EA,
  VCS_RESULT_OK_4 = 0x70e,
} VCS_RESULT;

typedef enum
{
  CMD_SEND,
  CMD_RECV,
  CMD_STATES,
} CommandState;

enum PROVISION_STATES
{
  UNPROVISIONED_A = 0,
  UNPROVISIONED_B = 1,
  PROVISIONED = 3
};

enum PRODUCT_IDS
{
  PROD_ID1 = '5',
  PROD_ID2 = '8',
  PROD_ID3 = ':',
  PROD_ID4 = '<',
  PROD_ID5 = 'A',
  BOOTLOADER_A = 'B',
  BOOTLOADER_B = 'C',
  PROD_ID6 = 'D',
  BOOTLOADER_C = 'F',
  BOOTLOADER_D = 'G',
};

enum HOST_DATA_TAGS
{
  HOST_DATA_TAG_VERSION = 1,
  HOST_DATA_TAG_PAIRED_DATA = 2,
};

enum PAIR_DATA_TAGS
{
  PAIR_DATA_TAG_VERSION = 0,
  PAIR_DATA_TAG_HOST_CERT = 1,
  PAIR_DATA_TAG_PRIVATE_KEY = 2,
  PAIR_DATA_TAG_SENSOR_CERT = 3,
  PAIR_DATA_TAG_PUB_KEY_SEC_DATA = 4,
  PAIR_DATA_TAG_SSI_STORAGE_PSK_ID = 5,
};

enum VCSFW_STORAGE_TUDOR_PART_IDS
{
  VCSFW_STORAGE_TUDOR_PART_ID_SSFS = 1,
  VCSFW_STORAGE_TUDOR_PART_ID_HOST = 2,
};

typedef enum
{
  OBJ_TYPE_USERS = 1,
  OBJ_TYPE_TEMPLATES = 2,
  OBJ_TYPE_PAYLOADS = 3,
} ObjType;

enum ENROLL_TAGS
{
  ENROLL_TAG_TEMPLATE_ID = 0,
  ENROLL_TAG_USER_ID = 1,
  ENROLL_TAG_FINGER_ID = 2,
};

enum ENROLL_SUBCMDS
{
  ENROLL_SUBCMD_START = 1,
  ENROLL_SUBCMD_ADD_IMAGE = 2,
  ENROLL_SUBCMD_COMMIT = 3,
  ENROLL_SUBCMD_FINISH = 4,
};

enum CAPTURE_FLAGS
{
  CAPTURE_FLAG_AUTH = 7,
  CAPTURE_FLAG_ENROLL = 15,
};

enum IDENTIFY_MATCH_SUBCMDS
{
  IDENTIFY_MATCH_SUBCMD_WBF_MATCH = 1,
  IDENTIFY_MATCH_SUBCMD_CONDITIONAL_WBF_MATCH = 3,
};

enum SENSOR_EVENT_TYPES
{
  NO_EVENTS = 0,
  EV_FINGER_DOWN = 1U << 1,
  EV_FINGER_UP = 1U << 2,
  EV_3 = 1U << 3, // unused
  EV_4 = 1U << 4, // unused
  EV_5 = 1U << 5, // unused
  EV_6 = 1U << 6, // unused
  EV_7 = 1U << 7, // unused
  EV_8 = 1U << 8, // unused
  EV_9 = 1U << 9, // unused
  EV_FRAME_READY = 1U << 24,
};

typedef enum
{
  MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE = 0x1,
  MIS_IMAGE_METRICS_IMG_QUALITY = 0x10000,
} ImageMetricsType;

/* SSM task states */

typedef enum
{
  CLEAR_STORAGE_DB2_FORMAT,
  CLEAR_STORAGE_COMPLETE,
  CLEAR_STORAGE_NUM_STATES,
} ClearStorageState;

typedef enum
{
  CLOSE_EVENT_MASK_NONE,
  CLOSE_TLS_SESSION_CLOSE,
  CLOSE_NUM_STATES,
} CloseState;

typedef enum
{
  DELETE_GET_USER_ID,
  DELETE_DELETE_TEMPLATE,
  DELETE_DELETE_USER,
  DELETE_NUM_STATES,
} DeleteState;

typedef enum
{
  ENROLL_ENROLL_START,
  ENROLL_SET_EVENT_FINGER_UP,
  ENROLL_WAIT_FINGER_UP,
  ENROLL_SET_EVENT_FRAME_READY,
  ENROLL_SEND_FRAME_ACQUIRE,
  ENROLL_SET_EVENT_FINGER_DOWN,
  ENROLL_WAIT_FINGER_DOWN,
  ENROLL_SET_EVENT_NONE,
  ENROLL_SEND_FRAME_FINISH,
  ENROLL_SEND_ADD_IMAGE,
  ENROLL_ADD_ENROLLMENT,
  ENROLL_ENROLL_FINISH,
  ENROLL_REPORT,
  ENROLL_NUM_STATES,
} EnrollState;

typedef enum
{
  IDENTIFY_VERIFY_SET_EVENT_FRAME_READY,
  IDENTIFY_VERIFY_SEND_FRAME_ACQUIRE,
  IDENTIFY_VERIFY_SET_EVENT_FINGER_DOWN,
  IDENTIFY_VERIFY_WAIT_FINGER_DOWN,
  IDENTIFY_VERIFY_SET_EVENT_NONE,
  IDENTIFY_VERIFY_SEND_FRAME_FINISH,
  IDENTIFY_VERIFY_IMAGE_METRICS,
  IDENTIFY_VERIFY_IDENTIFY_MATCH,
  IDENTIFY_VERIFY_COMPLETE,
  IDENTIFY_VERIFY_NUM_STATES,
} VerifyState;

typedef enum
{
  LIST_DB2_GET_DB_INFO,
  LIST_DB2_CLEANUP,
  LIST_DB2_GET_TEMPLATES_LIST,
  LIST_DB2_GET_PAYLOAD_LIST,
  LIST_DB2_GET_PAYLOAD_INFO,
  LIST_DB2_GET_PAYLOAD_DATA,
  LIST_REPORT,
  LIST_NUM_STATES,
} ListState;

typedef enum
{
  OPEN_TLS_STATUS,
  OPEN_HANDLE_TLS_STATUSES,
  OPEN_FORCE_TLS_CLOSE,
  OPEN_GET_VERSION,
  OPEN_EXIT_BOOTLOADER,
  OPEN_LOAD_SENSOR_KEY,
  OPEN_LOAD_PAIRING_DATA,
  OPEN_SEND_PAIR,
  OPEN_SAVE_PAIRING_DATA,
  OPEN_VERIFY_SENSOR_CERTIFICATE,
  OPEN_TLS_ESTABLISH,
  OPEN_TLS_SEND_DATA,
  OPEN_SET_EVENT_MASK,
  OPEN_NUM_STATES,
} OpenState;

typedef enum
{
  BOOTLOADER_MODE_EXIT = 0,
  BOOTLOADER_MODE_ENTER,
} BootloaderModeEnterExit;

typedef guint8 Db2Id[DB2_ID_SIZE];
typedef guint8 FingerId;
/* NOTE: fp_user_id is used in place of winbio_sid used in windows driver */
/* Fp* as a different user_id is used in DB2 */
typedef char FpUserId[WINBIO_SID_SIZE];

typedef struct
{
  guint32 build_time;
  guint32 build_num;

  guint8 version_major;
  guint8 version_minor;
  guint8 target;
  guint8 product_id;

  guint8 silicon_revision;
  guint8 formal_release;
  guint8 platform;
  guint8 patch;

  guint8 serial_number[6];
  guint8 security;
  guint8 interface;
  guint16 device_type;
  guint8 provision_state;
} MisVersion;

typedef struct
{
  guint16 progress;
  /* not using template id as it is soemtimes missing */
  guint32 quality;
  guint32 redundant;
  guint32 rejected;
  guint32 template_cnt;
  guint16 enroll_quality;
  guint32 status;
  /* NOTE: this may contain more information than only has fixed pattern */
  guint32 has_fixed_pattern;
} EnrollStats;

typedef struct
{
  guint16 dummy;
  guint16 version_major;
  guint16 version_minor;
  guint32 partition_version;
  guint16 uop_length;
  guint16 top_length;
  guint16 pop_length;
  guint16 template_object_size;
  guint16 payload_object_slot_size;
  guint16 num_current_users;
  guint16 num_deleted_users;
  guint16 num_available_user_slots;
  guint16 num_current_templates;
  guint16 num_deleted_templates;
  guint16 num_available_template_slots;
  guint16 num_current_payloads;
  guint16 num_deleted_payloads;
  guint16 num_available_payload_slots;
} Db2Info;

typedef struct
{
  GPtrArray *list_result;

  guint16 num_current_users;
  guint16 num_current_templates;
  guint16 num_current_payloads;

  GPtrArray *list_template_id;
  GPtrArray *list_payload_id;

  Db2Id *current_template_id;
  Db2Id *current_payload_id;
  guint32 current_payload_size;

  gboolean cleanup_required;
} ListData;

typedef struct
{
  FpPrint *print;
  Db2Id template_id;
  FpUserId fp_user_id;
  FingerId finger_id;
  gint frame_acquire_retry_idx;
} EnrollData;

typedef struct
{
  gboolean tried_to_exit_bootloader_mode;
  EVP_PKEY *pub_key;
} OpenData;

typedef struct
{
  Db2Id template_id;
  Db2Id user_id;
} DeleteData;

typedef struct
{
  gint frame_acquire_retry_idx;
} VerifyIdentifyData;
