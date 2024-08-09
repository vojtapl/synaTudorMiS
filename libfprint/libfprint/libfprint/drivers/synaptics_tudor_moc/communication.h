/*
 * TODO: header
 */

#pragma once

#include "device.h"
#include <glib.h>

/* Commands ================================================================ */

/* known command IDs */
#define VCSFW_CMD_GET_VERSION 0x01
#define VCSFW_CMD_RESET 0x05
#define VCSFW_CMD_PEEK 0x07
#define VCSFW_CMD_POKE 0x08
#define VCSFW_CMD_PROVISION 0x0e
#define VCSFW_CMD_RESET_OWNERSHIP 0x10
#define VCSFW_CMD_GET_STARTINFO 0x19
#define VCSFW_CMD_LED_EX2 0x39
#define VCSFW_CMD_STORAGE_INFO_GET 0x3e
#define VCSFW_CMD_STORAGE_PART_FORMAT 0x3f
#define VCSFW_CMD_STORAGE_PART_READ 0x40
#define VCSFW_CMD_STORAGE_PART_WRITE 0x41
// non-original name
#define VCSFW_CMD_TLS_DATA 0x44
#define VCSFW_CMD_DB_OBJECT_CREATE 0x47
#define VCSFW_CMD_TAKE_OWNERSHIP_EX2 0x4f
#define VCSFW_CMD_GET_CERTIFICATE_EX 0x50
#define VCSFW_CMD_TIDLE_SET 0x57
// #define exit/enter bootloader mode 0x69
#define VCSFW_CMD_BOOTLDR_PATCH 0x7d
#define VCSFW_CMD_FRAME_READ 0x7f
#define VCSFW_CMD_FRAME_ACQ 0x80
#define VCSFW_CMD_FRAME_FINISH 0x81
#define VCSFW_CMD_FRAME_STATE_GET 0x82
#define VCSFW_CMD_EVENT_CONFIG 0x86
#define VCSFW_CMD_EVENT_READ 0x87
#define VCSFW_CMD_FRAME_STREAM 0x8b
#define VCSFW_CMD_IOTA_FIND 0x8e
#define VCSFW_CMD_PAIR 0x93
#define VCSFW_CMD_ENROLL 0x96
// non-original name
#define VCSFW_CMD_IDENTIFY_MATCH 0x99
// non-original name
#define VCSFW_CMD_GET_IMAGE_METRICS 0x9d
#define VCSFW_CMD_DB2_GET_DB_INFO 0x9e
#define VCSFW_CMD_DB2_GET_OBJECT_LIST 0x9f
#define VCSFW_CMD_DB2_GET_OBJECT_INFO 0xa0
#define VCSFW_CMD_DB2_GET_OBJECT_DATA 0xa1
#define VCSFW_CMD_DB2_WRITE_OBJECT 0xa2
#define VCSFW_CMD_DB2_DELETE_OBJECT 0xa3
// non-original name
#define VCSFW_CMD_DB2_CLEANUP 0xa4
#define VCSFW_CMD_DB2_FORMAT 0xa5
// #define ? 0xa6
// non-original name
#define VCSFW_CMD_RESET_SBL_MODE 0xaa
#define VCSFW_CMD_SSO 0xac
#define VCSFW_CMD_OPINFO_GET 0xae
#define VCSFW_CMD_HW_INFO_GET 0xaf

/* other constants */
#define SENSOR_FW_CMD_HEADER_LEN 1
#define SENSOR_FW_REPLY_HEADER_LEN 2

#define ENROLL_SUBCMD_START 1
#define ENROLL_SUBCMD_ADD_IMAGE 2
#define ENROLL_SUBCMD_COMMIT 3
#define ENROLL_SUBCMD_FINISH 4

/* Response statuses ========================================================*/

/* here are known response names; in original code others are considered
 * a malfunction of the fingerprint sensor */
#define RESPONSE_OK_1 0x000
#define VCS_RESULT_SENSOR_BAD_CMD 0x401
#define VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_1 0x403
#define VCS_RESULT_GEN_OPERATION_DENIED 0x404
#define RESPONSE_BAD_PARAM_1 0x405
#define RESPONSE_BAD_PARAM_2 0x406
#define RESPONSE_BAD_PARAM_3 0x407
#define RESPONSE_OK_2 0x412
#define VCS_RESULT_MATCHER_MATCH_FAILED 0x509
#define VCS_RESULT_SENSOR_FRAME_NOT_READY 0x5B6
#define RESPONSE_OK_3 0x5CC
#define VCS_RESULT_DB_FULL 0x680
#define VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 0x683
/*this name is deduced*/
#define RESPONSE_PROCESSING_FRAME 0x6EA
#define UNKNOWN_RESPONSE_ON_WHICH_SEND_AGAIN 0x48c

/* USB defines ==============================================================*/

#define USB_EP_REQUEST 0x01
#define USB_EP_REPLY 0x81
#define USB_EP_FINGERPRINT 0x82
#define USB_EP_INTERRUPT 0x83
#define USB_ASYNC_MESSAGE_PENDING 0x4
#define USB_INTERRUPT_DATA_SIZE 7
#define MAX_TRANSFER_LEN 263 + 1 /* SPI Header */ + 2 /* VCSFW header */
#define USB_TRANSFER_WAIT_TIMEOUT_MS 1000

/* Response structs =========================================================*/

typedef guint8 tuid[16];

typedef struct {
   guint32 fw_build_time;
   guint32 fw_build_num;

   guint8 fw_version_major;
   guint8 fw_version_minor;
   guint8 fw_target;
   guint8 product_id;

   guint8 silicon_revision;
   guint8 formal_release;
   guint8 platform;
   guint8 patch;

   guint8 serial_number[6];

   guint8 security;
   guint8 interface;
   guint32 unused1;
   guint16 unused2;
   guint8 device_type;
   guint16 unused3;
   guint8 provision_state;
} get_version_t;

typedef struct {
   guint16 progress;
   guint32 quality;
   guint32 redundant;
   guint32 rejected;
   guint32 template_cnt;
   guint16 enroll_quality;
   guint32 status;
   guint32 smt_like_has_fixed_pattern;
   tuid tuid;

} enroll_add_image_t;

/* Functions ================================================================*/
gboolean send_get_version(FpiDeviceSynapticsMoc *self, get_version_t *resp,
                          GError *error);

gboolean send_frame_acq(FpiDeviceSynapticsMoc *self, guint8 frame_flags,
                        GError *error);

gboolean send_frame_finish(FpiDeviceSynapticsMoc *self, GError *error);

gboolean send_enroll_start(FpiDeviceSynapticsMoc *self, GError *error);

gboolean send_enroll_add_image(FpiDeviceSynapticsMoc *self,
                               enroll_add_image_t *resp, GError *error);

gboolean send_enroll_commit(FpiDeviceSynapticsMoc *self,
                            guint8 *enroll_commit_data,
                            gsize enroll_commit_data_size, GError *error);

gboolean send_enroll_finish(FpiDeviceSynapticsMoc *self, GError *error);

gboolean send_identify_match(FpiDeviceSynapticsMoc *self, tuid *tuid_list,
                             gsize tuid_list_size, GError *error);

gboolean send_get_image_metrics(FpiDeviceSynapticsMoc *self, guint32 type,
                                guint32 *recv_value, GError *error);

gboolean send_event_config(FpiDeviceSynapticsMoc *self, guint32 event_mask,
                           GError *error);

gboolean send_event_read(FpiDeviceSynapticsMoc *self, guint8 *event_buffer,
                         gsize event_buffer_size, gint *num_events,
                         GError *error);

gboolean synaptics_secure_connect(FpiDeviceSynapticsMoc *self,
                                  guint8 *send_data, gsize send_len,
                                  guint8 **recv_data, gsize *recv_len,
                                  gboolean check_status);

gboolean send_reset(FpiDeviceSynapticsMoc *self, GError *error);
