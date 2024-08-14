#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include <glib.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

G_DECLARE_FINAL_TYPE(FpiDeviceSynapticsMoc, fpi_device_synaptics_moc, FPI,
                     DEVICE_SYNAPTICS_MOC, FpDevice)

#define CERTIFICATE_KEY_SIZE 68
#define SENSOR_EVENT_QUEUE_SIZE 5

typedef enum {
   TLS_HANDSHAKE_PREPARE = 0,
   TLS_HANDSHAKE_START,
   TLS_HANDSHAKE_END,

   TLS_HANDSHAKE_ALERT,
   TLS_HANDSHAKE_FAILED,
   TLS_HANDSHAKE_FINISHED,
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

typedef struct {
   guint16 status;
   guint32 payload_len;
   guint8 *payload;
} msg_resp_t;

typedef struct {
   guint32 payload_len;
   guint8 *payload;
} msg_send_t;

typedef void (*CmdMsgCallback)(FpiDeviceSynapticsMoc *self, msg_resp_t *resp,
                               GError *error);

typedef struct {
   msg_send_t send;
   msg_resp_t resp;
} transmission_ssm_data;

typedef struct {
   gboolean established;
   guint8 *session_id;
   guint8 session_id_len;

   tls_handshake_state_t handshake_state;

   guint8 version_major;
   guint8 version_minor;

   guint32 server_timestamp;

   guint16 ciphersuit;
   guint8 compression_method;

   guint8 client_random[32]; // note: the first 4 bytes are time
   guint8 server_random[32]; // note: the first 4 bytes are time
   guint8 derive_input[32 * 2];
   gnutls_datum_t master_secret;
   gnutls_datum_t encryption_key;
   gnutls_datum_t decryption_key;
   gnutls_datum_t encryption_iv;
   gnutls_datum_t decryption_iv;
   guint tag_size;

   guint64 encrypt_seq_num;
   guint64 decrypt_seq_num;

   gnutls_cipher_algorithm_t cipher_alg;
   gboolean remote_sends_encrypted;

   // for hashing
   guint8 *sent_handshake_msgs;
   gsize sent_handshake_msgs_size;
   gsize sent_handshake_msgs_alloc_size;
} tls_t;

typedef struct {
   guint16 num_current_users;
   guint16 num_current_templates;
   guint16 num_current_payloads;

} storage_t;

typedef struct {
   guint16 magic;
   guint16 curve;
   guint8 pubkey_x[CERTIFICATE_KEY_SIZE];
   guint8 pubkey_y[CERTIFICATE_KEY_SIZE];
   guint8 cert_type;
   guint16 sign_size;
   guint8 *sign_data;
} sensor_cert_t;

typedef struct {
   gboolean present;

   sensor_cert_t host_cert;
   sensor_cert_t sensor_cert;

   guint8 *sensor_cert_bytes;
   gsize sensor_cert_bytes_len;

   guint8 *host_cert_bytes;
   gsize host_cert_bytes_len;

   gnutls_privkey_t private_key;
} pairing_data_t;

struct _FpiDeviceSynapticsMoc {
   FpDevice parent;

   // TODO: not aplicable?
   // guint8                cmd_seq_num;
   // guint8                last_seq_num;

   FpiSsm *task_ssm;
   FpiSsm *cmd_ssm;
   transmission_ssm_data cmd_ssm_data;

   FpiUsbTransfer *cmd_pending_transfer;
   gboolean cmd_complete_on_removal;
   gboolean cmd_suspended;
   guint8 id_idx;

   // bmkt_sensor_version_t mis_version;

   gboolean action_starting;
   GCancellable *interrupt_cancellable;

   gint enroll_stage;
   gboolean finger_on_sensor;
   GPtrArray *list_result;

   // TLS session things
   tls_t tls;

   pairing_data_t pairing_data;

   // Everything stored on sensor
   storage_t storage;

   // FIXME: init these to zero somewhere
   guint16 event_seq_num;      // current host event sequence number
   guint16 num_pending_events; // number of pending events which are unread
   gboolean event_read_in_legacy_mode;
   guint num_events_in_queue;
   sensor_event_type_t event_queue[SENSOR_EVENT_QUEUE_SIZE];

   // struct syna_enroll_resp_data enroll_resp_data;
   // syna_state_t state;
   // GError *delay_error;
};
