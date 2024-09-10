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

/*
 * this implements needed tls functionality, because it seems that the Windows
 * driver implements some thigns differently
 */

#pragma once

#include "device.h"
#include <glib.h>
#include <gnutls/gnutls.h>

#define REQUEST_TLS_SESSION_STATUS 0x14
#define TLS_SESSION_STATUS_DATA_RESP_LEN 2
#define TLS_SESSION_STATUS_TIMEOUT_MS 1000

#define VERIFY_DATA_SIZE 12

#define TLS_PROTOCOL_VERSION_MAJOR 3
#define TLS_PROTOCOL_VERSION_MINOR 3

#define RECORD_HEADER_SIZE 5
#define ECC_KEY_SIZE 32
#define CERTIFICATE_SIZE_WITHOUT_SIGNATURE 142
#define CERTIFICATE_MAGIC 0x5f3f
#define CERTIFICATE_CURVE 23

#define MASTER_SECRET_SIZE 48
#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE 4
#define AES_GCM_TAG_SIZE 16

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

typedef struct {
   guint16 id;
   gnutls_mac_algorithm_t mac_algo;
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
   guint8 session_id[SESSION_ID_LEN];

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

gboolean establish_tls_session(FpiDeviceSynaTudorMoc *self, GError **error);

void tls_close_session(FpiDeviceSynaTudorMoc *self);

gboolean tls_wrap(FpiDeviceSynaTudorMoc *self, guint8 *ptext, gsize ptext_size,
                  guint8 **ctext, gsize *ctext_size, GError **error);

gboolean tls_unwrap(FpiDeviceSynaTudorMoc *self, guint8 *ctext,
                    gsize ctext_size, guint8 **ptext, gsize *ptext_size,
                    GError **error);

gboolean get_remote_tls_status(FpiDeviceSynaTudorMoc *self, gboolean *status,
                               GError **error);

gboolean verify_sensor_certificate(FpiDeviceSynaTudorMoc *self, GError **error);

gboolean load_sample_pairing_data(FpiDeviceSynaTudorMoc *self, GError **error);

void deinit_tls(FpiDeviceSynaTudorMoc *self);

gboolean handle_tls_statuses_for_sensor_and_host(FpiDeviceSynaTudorMoc *self,
                                                 GError **error);

void free_pairing_data(FpiDeviceSynaTudorMoc *self);

void pair(FpiDeviceSynaTudorMoc *self);

gboolean parse_certificate(const guint8 *data, const gsize len, cert_t *cert);

void send_get_remote_tls_status(FpiDeviceSynaTudorMoc *self);

void tls_handshake_state_prepare(FpiDeviceSynaTudorMoc *self);
void tls_handshake_state_start(FpiDeviceSynaTudorMoc *self);
void tls_handshake_state_end(FpiDeviceSynaTudorMoc *self);
void tls_handshake_cleanup(FpiDeviceSynaTudorMoc *self);
