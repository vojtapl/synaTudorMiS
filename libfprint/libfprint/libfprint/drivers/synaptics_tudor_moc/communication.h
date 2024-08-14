/*
 * TODO: header
 */

#pragma once

#include "device.h"
#include "other_constants.h"
#include <glib.h>

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
#define USB_TRANSFER_WAIT_TIMEOUT_MS 1000

/* others ===================================================================*/

#define WRAP_RESPONSE_ADDITIONAL_SIZE 0x45
#define MATCH_STATS_SIZE 36
#define EVENT_WAIT_TIMEOUT_MS 60000
#define SENSOR_FW_CMD_HEADER_LEN 1
#define SENSOR_FW_REPLY_HEADER_LEN 2
#define DB2_ID_SIZE 16

/* Commands ================================================================ */

/* known command IDs */
typedef enum {
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
   VCSFW_CMD_TLS_DATA = 0x44, // non-original name
   VCSFW_CMD_DB_OBJECT_CREATE = 0x47,
   VCSFW_CMD_TAKE_OWNERSHIP_EX2 = 0x4f,
   VCSFW_CMD_GET_CERTIFICATE_EX = 0x50,
   VCSFW_CMD_TIDLE_SET = 0x57,
   // exit/enter bootloader mode 0x69
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
   VCSFW_CMD_IDENTIFY_MATCH = 0x99,    // non-original name
   VCSFW_CMD_GET_IMAGE_METRICS = 0x9d, // non-original name
   VCSFW_CMD_DB2_GET_DB_INFO = 0x9e,
   VCSFW_CMD_DB2_GET_OBJECT_LIST = 0x9f,
   VCSFW_CMD_DB2_GET_OBJECT_INFO = 0xa0,
   VCSFW_CMD_DB2_GET_OBJECT_DATA = 0xa1,
   VCSFW_CMD_DB2_WRITE_OBJECT = 0xa2,
   VCSFW_CMD_DB2_DELETE_OBJECT = 0xa3,
   VCSFW_CMD_DB2_CLEANUP = 0xa4, // non-original name
   VCSFW_CMD_DB2_FORMAT = 0xa5,
   // ? 0xa6
   VCSFW_CMD_RESET_SBL_MODE = 0xaa, // non-original name
   VCSFW_CMD_SSO = 0xac,
   VCSFW_CMD_OPINFO_GET = 0xae,
   VCSFW_CMD_HW_INFO_GET = 0xaf,
} vcsfw_cmd_t;

typedef enum {
   ENROLL_SUBCMD_START = 1,
   ENROLL_SUBCMD_ADD_IMAGE = 2,
   ENROLL_SUBCMD_COMMIT = 3,
   ENROLL_SUBCMD_FINISH = 4,
} enroll_subcmd_t;

/* Response structs =========================================================*/

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
   // 7 bytes unused
   guint8 device_type;
   // 2 bytes unused
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
   db2_id_t tuid;

} enroll_add_image_t;

typedef struct {
   db2_id_t tuid;
   guint8 *user_id;
   guint16 finger_id;
} match_stat_t;

typedef struct {
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

} db2_info_t;

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

gboolean send_identify_match(FpiDeviceSynapticsMoc *self,
                             db2_id_t *tuids_to_match, gsize number_of_tuids,
                             gboolean *matched, enrollment_t *match,
                             GError *error);

gboolean send_get_image_metrics(FpiDeviceSynapticsMoc *self, guint32 type,
                                guint32 *recv_value, GError *error);

gboolean send_event_config(FpiDeviceSynapticsMoc *self, guint32 event_mask,
                           GError *error);

gboolean send_event_read(FpiDeviceSynapticsMoc *self, guint32 *recv_event_mask,
                         GError *error);

gboolean synaptics_secure_connect(FpiDeviceSynapticsMoc *self,
                                  guint8 *send_data, gsize send_len,
                                  guint8 **recv_data, gsize *recv_len,
                                  const gboolean check_status);

gboolean send_reset(FpiDeviceSynapticsMoc *self, GError *error);

gboolean send_db2_info(FpiDeviceSynapticsMoc *self, GError *error);

gboolean send_db2_format(FpiDeviceSynapticsMoc *self, GError *error);

gboolean add_enrollment(FpiDeviceSynapticsMoc *self, guint8 *user_id,
                        guint8 finger_id, db2_id_t tuid, GError *error);

gboolean send_db2_delete_object(FpiDeviceSynapticsMoc *self,
                                obj_type_t obj_type, db2_id_t *obj_id,
                                GError *error);

gboolean send_db2_get_object_list(FpiDeviceSynapticsMoc *self,
                                  obj_type_t obj_type, db2_id_t obj_id,
                                  db2_id_t **obj_list, guint16 *obj_list_len,
                                  GError *error);

gboolean send_db2_get_object_info(FpiDeviceSynapticsMoc *self,
                                  obj_type_t obj_type, db2_id_t obj_id,
                                  guint8 **obj_info, gsize *obj_info_size,
                                  GError *error);

gboolean send_db2_get_object_data(FpiDeviceSynapticsMoc *self,
                                  obj_type_t obj_type, db2_id_t obj_id,
                                  guint8 **obj_data, guint *obj_data_size,
                                  GError *error);

gboolean get_event_data(FpiDeviceSynapticsMoc *self, guint8 *event_buffer,
                        gsize event_buffer_size);

gboolean wait_for_events_blocking(FpiDeviceSynapticsMoc *self,
                                  guint32 event_mask, GError *error);
