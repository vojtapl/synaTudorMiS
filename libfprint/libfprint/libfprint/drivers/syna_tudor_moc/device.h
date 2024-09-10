/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * Copyright (c) 2024 Vojtěch Pluskal
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

#include "fpi-device.h"
#include "fpi-ssm.h"
#include <glib.h>
#include <gnutls/gnutls.h>

G_DECLARE_FINAL_TYPE(FpiDeviceSynaTudorMoc, fpi_device_synaptics_moc, FPI,
                     DEVICE_SYNA_TUDOR_MOC, FpDevice)

#define SESSION_ID_LEN 7
#define CERTIFICATE_KEY_SIZE 68
#define SIGNATURE_SIZE 256
#define PROVISION_STATE_PROVISIONED 3

#define WINBIO_SID_SIZE 76
#define DB2_ID_SIZE 16

#define EVENT_BUFFER_SIZE 8

typedef enum {
   OBJ_TYPE_USERS = 1,
   OBJ_TYPE_TEMPLATES = 2,
   OBJ_TYPE_PAYLOADS = 3,
} obj_type_t;

typedef enum {
   MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE = 0x1,
   MIS_IMAGE_METRICS_IMG_QUALITY = 0x10000,
} img_metrics_type_t;

typedef guint8 db2_id_t[DB2_ID_SIZE];
/* NOTE: user_id is used in place of winbio_sid used in windows driver */
typedef guint8 user_id_t[WINBIO_SID_SIZE];

typedef struct {
   user_id_t user_id;
   db2_id_t template_id;
   guint8 finger_id;
} enrollment_t;

typedef struct {
   guint16 progress;
   db2_id_t template_id;
   guint32 quality;
   guint32 redundant;
   guint32 rejected;
   guint32 template_cnt;
   guint16 enroll_quality;
   guint32 status;
   guint32 smt_like_has_fixed_pattern;
} enroll_stats_t;

typedef enum {
   TLS_HS_STATE_PREPARE = 0,
   TLS_HS_STATE_START,
   TLS_HS_STATE_END,
   TLS_HS_STATE_ALERT,
   TLS_HS_STATE_FAILED,
   TLS_HS_STATE_FINISHED,
} tls_handshake_state_t;

typedef enum {
   NO_EVENTS = 0,
   EV_FINGER_DOWN = 1U << 1,
   EV_FINGER_UP = 1U << 2,
   /* events EV_3 to EV_9 are unused, but are here for completeness */
   EV_3 = 1U << 3,
   EV_4 = 1U << 4,
   EV_5 = 1U << 5,
   EV_6 = 1U << 6,
   EV_7 = 1U << 7,
   EV_8 = 1U << 8,
   EV_9 = 1U << 9,
   EV_FRAME_READY = 1U << 24,
   NUM_EVENTS,
} sensor_event_type_t;

typedef enum {
   TLS_CERT_TYPE_RSA_SIGN = 1,
   TLS_CERT_TYPE_DSS_SIGN = 2,
   TLS_CERT_TYPE_RSA_FIXED_DH = 3,
   TLS_CERT_TYPE_DSS_FIXED_DH = 4,
   TLS_CERT_TYPE_ECDSA_SIGN = 64,
   TLS_CERT_TYPE_RSA_FIXED_ECDH = 65,
   TLS_CERT_TYPE_ECDSA_FIXED_ECDH = 66,
} tls_certificate_type_t;

/* state storage structs =================================================== */

typedef struct {
   gboolean usb_device_claimed;
   gboolean tried_to_close_tls_session;

} open_ssm_data_t;

typedef struct {
   enrollment_t match_enrollment;
   enroll_stats_t enroll_stats;
   guint32 event_mask_to_read;
   GError *error;
} enroll_ssm_data_t;

typedef struct {
   guint image_quality;
   gboolean matched;
   enrollment_t match_enrollment;
   guint32 event_mask_to_read;

   gboolean verify_template_id_present;
   db2_id_t verify_template_id;
} auth_ssm_data_t;

typedef struct {
   db2_id_t *template_id_list;
   guint template_id_cnt;
   guint current_template_id_idx;

   GArray *payload_id_list;
   guint current_payload_id_idx;

   GPtrArray *fp_print_array;
} list_ssm_data_t;

typedef struct {
   db2_id_t template_id;
} delete_ssm_data_t;

/* ========================================================================= */

typedef struct {
   gboolean established;
   guint8 session_id[SESSION_ID_LEN];

   guint8 version_major;
   guint8 version_minor;

   guint16 ciphersuit;
   guint8 compression_method;
   gnutls_mac_algorithm_t mac_algo;

   guint8 client_random[32]; /* note: the first 4 bytes are time */
   guint8 server_random[32]; /* note: the first 4 bytes are time */
   guint8 derive_input[32 * 2];
   gnutls_datum_t master_secret;
   gnutls_datum_t encryption_key;
   gnutls_datum_t decryption_key;
   gnutls_datum_t encryption_iv;
   gnutls_datum_t decryption_iv;
   guint tag_size;

   guint64 encrypt_seq_num;
   guint64 decrypt_seq_num;

   tls_certificate_type_t requested_cert;
   gnutls_cipher_algorithm_t cipher_alg;
   gboolean remote_sends_encrypted;

   tls_handshake_state_t handshake_state;
   gnutls_alert_level_t alert_level;
   gnutls_alert_description_t alert_desc;

   /* for hashing */
   guint8 *sent_handshake_msgs;
   gsize sent_handshake_msgs_size;
   gsize sent_handshake_msgs_alloc_size;
} tls_t;

typedef struct {
   guint16 num_current_users;
   guint16 num_current_templates;
   guint16 num_current_payloads;
} storage_t;

#pragma pack(push, 1)
typedef struct {
   guint16 magic;
   guint16 curve;
   guint8 pubkey_x[CERTIFICATE_KEY_SIZE];
   guint8 pubkey_y[CERTIFICATE_KEY_SIZE];
   guint8 padding;
   guint8 cert_type;
   guint16 sign_size;
   guint8 sign_data[SIGNATURE_SIZE];
} cert_t;
#pragma pack(pop)

typedef struct {
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
   guint16 security;
   guint8 interface;
   /* 7 bytes unused */
   guint8 device_type;
   /* 2 bytes unused */
   guint8 provision_state;
} mis_version_t;

typedef struct {
   gboolean present;

   cert_t sensor_cert;
   cert_t host_cert;

   gboolean private_key_initialized;
   gnutls_privkey_t private_key;
} pairing_data_t;

typedef struct {
   guint16 seq_num;     /* current host event sequence number */
   guint16 num_pending; /* number of pending events which are unread */
   gboolean read_in_legacy_mode;
} events_t;

typedef void (*CmdCallback)(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                            gsize recv_size, GError *error);

typedef struct {
   guint8 *send_data;
   gsize send_size;

   guint8 *recv_data;
   gsize recv_size;
   gsize expected_recv_size;

   gboolean check_status;
   guint8 cmd_id;

   CmdCallback callback;
} cmd_ssm_data_t;

typedef enum {
   OPEN_STATE_GET_REMOTE_TLS_STATUS,
   OPEN_STATE_HANDLE_TLS_STATUSES,
   OPEN_STATE_FORCE_CLOSE_SENSOR_TLS_SESSION,
   OPEN_STATE_CHECK_CLOSE_SUCCESS,
   OPEN_STATE_SEND_GET_VERSION,
   OPEN_STATE_EXIT_BOOTLOADER_MODE,
   OPEN_STATE_LOAD_PAIRING_DATA,
   OPEN_STATE_VERIFY_SENSOR_CERTIFICATE,
   OPEN_STATE_TLS_HS_PREPARE,
   OPEN_STATE_TLS_HS_STATE_SEND_CLIENT_HELLO,
   OPEN_STATE_TLS_HS_STATE_END,
   OPEN_STATE_TLS_HS_STATE_FINISHED,
   OPEN_STATE_TLS_HS_STATE_ALERT,
   OPEN_STATE_TLS_HS_STATE_FAILED,
   OPEN_NUM_STATES,
} open_state_t;
/* response storage structs ================================================ */

typedef struct {
   gboolean matched;
   enrollment_t matched_enrollment;
} match_result_t;

typedef struct {
   guint32 ipl_finger_coverage;
} img_metrics_ipl_finger_coverage_t;

typedef struct {
   guint32 img_quality;
   guint32 sensor_coverage;
} img_metrics_matcher_stats;

typedef union {
   img_metrics_ipl_finger_coverage_t ipl_finger_coverage;
   img_metrics_matcher_stats matcher_stats;
} img_metrics_data_t;

typedef struct {
   img_metrics_type_t type;
   img_metrics_data_t data;
} img_metrics_t;

typedef struct {
   guint16 len;
   db2_id_t *obj_list;
} db2_obj_list_t;

typedef struct {
   guint32 size;
   guint8 *data;
} db2_obj_data_t;

typedef struct {
   guint8 *data;
   gsize size;
} raw_resp_t;

typedef union {
   enroll_stats_t enroll_stats;
   match_result_t match_result;
   img_metrics_t img_metrics;
   db2_obj_list_t db2_obj_list;
   db2_obj_data_t db2_obj_data;
   guint32 read_event_mask;
   guint8 event_buffer[EVENT_BUFFER_SIZE];
   raw_resp_t raw_resp;
   gboolean cleanup_required;
   gboolean sensor_is_in_tls_session;
} parsed_recv_data;

/* ========================================================================= */

typedef enum {
   CAPTURE_FLAGS_AUTH = 7,
   CAPTURE_FLAGS_ENROLL = 15,
} capture_flags_t;

typedef struct {
   guint num_retries;
   guint retries_left;
   capture_flags_t last_capture_flags;
} frame_acq_config_t;

struct _FpiDeviceSynaTudorMoc {
   FpDevice parent;

   GCancellable *interrupt_cancellable;

   FpiSsm *task_ssm;
   FpiSsm *subtask_ssm;
   FpiSsm *cmd_ssm;
   /* stores everything needed for sending/receiving of a command to sensor */
   FpiUsbTransfer *cmd_transfer;
   /* stores parsed data received from sending a command if response cannot be
    * stored to self (e.g. not mis_version)*/
   parsed_recv_data parsed_recv_data;
   frame_acq_config_t frame_acq_config;

   mis_version_t mis_version;
   pairing_data_t pairing_data;
   tls_t tls;         /* TLS session things */
   storage_t storage; /* sensor storage */
   events_t events;
};
