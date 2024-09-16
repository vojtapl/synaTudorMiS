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

#include <glib.h>
#include <openssl/ec.h>

#define CERTIFICATE_SIZE 400
#define CERTIFICATE_DATA_SIZE 142

#define ECC_KEY_SIZE 32
#define CERTIFICATE_MAGIC 0x5F3F
#define CERTIFICATE_CURVE 23

#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE 4
#define AES_GCM_TAG_SIZE 16

#define NONCE_SIZE 8

typedef struct
{
  guint16 magic;
  guint16 curve;
  guint8 *x;
  guint8 *y;
  EVP_PKEY *pub_key;
  guint8 cert_type;
  guint16 sign_size;
  guint8 *sign;
} Certificate;

typedef struct
{
  EVP_PKEY *client_key;
  guint8 *client_cert_raw;
  gsize client_cert_len;
  Certificate client_cert;
  guint8 *server_cert_raw;
  gsize server_cert_len;
  Certificate server_cert;
} SensorPairingData;

typedef struct _TlsSession TlsSession;

TlsSession *tls_session_new(void);
void tls_session_free(TlsSession *self);

void free_pairing_data(SensorPairingData *pairing_data);

gboolean tls_session_establish(TlsSession *self, GError **error);
gboolean tls_session_init(TlsSession *self, SensorPairingData *pairing_data,
                          GError **error);
gboolean tls_session_flush_send_buffer(TlsSession *self, guint8 **data,
                                       gsize *size, GError **error);
gboolean tls_session_has_data(TlsSession *self);
gboolean tls_session_receive_ciphertext(TlsSession *self, guint8 *data,
                                        gsize size, GError **error);
gboolean tls_session_wrap(TlsSession *self, guint8 *pdata, gsize pdata_size,
                          guint8 **cdata, gsize *cdata_size, GError **error);
gboolean tls_session_unwrap(TlsSession *self, guint8 *cdata, gsize cdata_size,
                            guint8 **pdata, gsize *pdata_size, GError **error);
gboolean tls_session_close(TlsSession *self, GError **error);

gboolean create_host_certificate(EVP_PKEY *server_key,
                                 guint8 **host_certificate_bytes,
                                 GError **error);
