/*
 * TODO: add header
 */

/*
 * this implements needed tls functionality, because it seems that the Windows
 * driver implements some thigns differently
 */

#pragma once

#include "device.h"
#include <glib.h>

#define REQUEST_TLS_SESSION_STATUS 0x14
#define TLS_SESSION_STATUS_DATA_RESP_LEN 2
#define TLS_SESSION_STATUS_TIMEOUT_MS 2000
#define TLS_SESSION_ID_LEN 7

// TLS 1.2 layer: sess "tls data" command
// TODO: TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
/* unusable:*/
// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
// TLS_RSA_WITH_AES_256_CBC_SHA256
// TLS_PSK_WITH_AES_256_CBC_SHA
// TLS_PSK_WITH_AES_128_GCM_SHA256

#define TLS_PROTOCOL_VERSION_MAJOR 3
#define TLS_PROTOCOL_VERSION_MINOR 3

#define RECORD_HEADER_SIZE 5

#define MASTER_SECRET_SIZE 48
#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE 4
#define AES_GCM_TAG_SIZE 16

typedef enum {
   TLS_ALERT_LVL_WARNING = 1,
   TLS_ALERT_LVL_FATAL = 2,
} tls_alert_level_t;

typedef enum {
   TLS_ALERT_DESC_CLOSE_NOTIFY = 0,
   TLS_ALERT_DESC_UNEXPECTED_MESSAGE = 10,
   TLS_ALERT_DESC_BAD_RECORD_MAC = 20,
   TLS_ALERT_DESC_DECRYPTION_FAILED_RESERVED = 21,
   TLS_ALERT_DESC_RECORD_OVERFLOW = 22,
   TLS_ALERT_DESC_DECOMPRESSION_FAILURE = 30,
   TLS_ALERT_DESC_HANDSHAKE_FAILURE = 40,
   TLS_ALERT_DESC_NO_CERTIFICATE_RESERVED = 41,
   TLS_ALERT_DESC_BAD_CERTIFICATE = 42,
   TLS_ALERT_DESC_UNSUPPORTED_CERTIFICATE = 43,
   TLS_ALERT_DESC_CERTIFICATE_REVOKED = 44,
   TLS_ALERT_DESC_CERTIFICATE_EXPIRED = 45,
   TLS_ALERT_DESC_CERTIFICATE_UNKNOWN = 46,
   TLS_ALERT_DESC_ILLEGAL_PARAMETER = 47,
   TLS_ALERT_DESC_UNKNOWN_CA = 48,
   TLS_ALERT_DESC_ACCESS_DENIED = 49,
   TLS_ALERT_DESC_DECODE_ERROR = 50,
   TLS_ALERT_DESC_DECRYPT_ERROR = 51,
   TLS_ALERT_DESC_EXPORT_RESTRICTION_RESERVED = 60,
   TLS_ALERT_DESC_PROTOCOL_VERSION = 70,
   TLS_ALERT_DESC_INSUFFICIENT_SECURITY = 71,
   TLS_ALERT_DESC_INTERNAL_ERROR = 80,
   TLS_ALERT_DESC_USER_CANCELED = 90,
   TLS_ALERT_DESC_NO_RENEGOTIATION = 100,
   TLS_ALERT_DESC_UNSUPPORTED_EXTENSION = 110,
   TLS_ALERT_DESC_CLOSE_NOTIFY2 = 166,
} tls_alert_description_t;

typedef enum {
   RECORD_TYPE_CHANGE_CIPHER_SPEC = 0x14,
   RECORD_TYPE_ALERT = 0x15,
   RECORD_TYPE_HANDSHAKE = 0x16,
   RECORD_TYPE_APPLICATION_DATA = 0x17,
} record_type_t;

typedef enum {
   HS_CLIENT_HELLO = 0x01,
   HS_SERVER_HELLO = 0x02,
   HS_CERTIFICATE = 0x0B,
   HS_SERVER_KEY_EXCHANGE = 0x0C,
   HS_CERTIFICATE_REQUEST = 0x0D,
   HS_SERVER_HELLO_DONE = 0x0E,
   HS_CERTIFICATE_VERIFY = 0x0F,
   HS_CLIENT_KEY_EXCHANGE = 0x10,
   HS_FINISHED = 0x14
} handshake_msg_type_t;

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
   guint16 id;

} cipher_suit_t;

typedef struct {
   guint16 id;
   guint16 len;
   guint8 *data;
} extension_t;

typedef struct {
   guint8 version_major;
   guint8 version_minor;
   guint32 current_timestamp;
   guint8 random[28];
   guint8 session_id[7];

   cipher_suit_t *cipher_suits;
   guint cipher_suit_cnt;

   extension_t *extensions;
   guint extension_cnt;
} hello_t;

typedef struct {
   guint8 type;
   guint8 version_major;
   guint8 version_minor;
   guint16 msg_len;
   guint8 *msg;
} record_t;

gboolean establish_tls_session(FpiDeviceSynaTudorMoc *self, GError *error);

gboolean tls_close_session(FpiDeviceSynaTudorMoc *self, GError *error);

gboolean tls_wrap(FpiDeviceSynaTudorMoc *self, guint8 *ptext, gsize ptext_size,
                  guint8 **ctext, gsize *ctext_size);

gboolean tls_unwrap(FpiDeviceSynaTudorMoc *self, guint8 *ctext,
                    gsize ctext_size, guint8 **ptext, gsize *ptext_size);

gboolean get_remote_tls_status(FpiDeviceSynaTudorMoc *self, gboolean *status,
                               GError *error);

gboolean verify_sensor_certificate(FpiDeviceSynaTudorMoc *self,
                                   gnutls_pubkey_t sensor_pubkey);

gboolean load_sample_pairing_data(FpiDeviceSynaTudorMoc *self);
