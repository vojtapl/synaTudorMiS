#pragma once

#include "fpi-device.h"
#include <glib.h>
#include <gnutls/gnutls.h>

G_DECLARE_FINAL_TYPE(FpiDeviceSynaTudorMoc, fpi_device_synaptics_moc, FPI,
                     DEVICE_SYNA_TUDOR_MOC, FpDevice)

#define CERTIFICATE_KEY_SIZE 68

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

typedef struct {
   guint16 status;
   guint32 payload_len;
   guint8 *payload;
} msg_resp_t;

typedef struct {
   guint32 payload_len;
   guint8 *payload;
} msg_send_t;

typedef void (*CmdMsgCallback)(FpiDeviceSynaTudorMoc *self, msg_resp_t *resp,
                               GError *error);

typedef struct {
   msg_send_t send;
   msg_resp_t resp;
} transmission_ssm_data;

typedef struct {
   gboolean established;
   guint8 *session_id;
   guint8 session_id_len;

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
} get_version_t;

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

typedef struct {
   guint16 seq_num;     /* current host event sequence number */
   guint16 num_pending; /* number of pending events which are unread */
   gboolean read_in_legacy_mode;
} events_t;

struct _FpiDeviceSynaTudorMoc {
   FpDevice parent;

   GCancellable *cancellable;

   get_version_t mis_version;
   pairing_data_t pairing_data;
   tls_t tls;         /* TLS session things */
   storage_t storage; /* sensor storage */
   events_t events;
};
