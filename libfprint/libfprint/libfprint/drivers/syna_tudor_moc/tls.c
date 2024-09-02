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

#include "communication.h"
#include "device.h"
#include "drivers_api.h"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-usb-transfer.h"
#include "sample_pairing_data.h"
#include "sensor_keys.h"
#include "tls.h"
#include "utils.h"
#include <gio/gio.h>
#include <glib.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

// #define TLS_DEBUG

/* Supported ciphersuites and extensions =================================== */

/* the only ciphersuite which seemed to be usable */
static cipher_suit_t tls_ecdh_ecdsa_with_aes_256_gcm_sha384 = {
    .id = 0xC02E,
    .mac_algo = GNUTLS_MAC_SHA384,
};
/* set supported curve to 0x17=23 */
static guint8 supported_groups_data[4] = {0x00, 0x02, 0x00, 0x17};
static extension_t supported_groups = {
    .id = 0xa, .len = 4, .data = supported_groups_data};
/* set ec_point_formats to 0 */
static guint8 ec_point_formats_data[2] = {0x01, 0x00};
static extension_t ec_point_formats = {
    .id = 0xb, .len = 2, .data = ec_point_formats_data};

/*===========================================================================*/

static gboolean write_record_header(FpiByteWriter *writer,
                                    const record_t *record)
{
   gboolean written = TRUE;

   written &= fpi_byte_writer_put_uint8(writer, record->type);
   written &= fpi_byte_writer_put_uint8(writer, record->version_major);
   written &= fpi_byte_writer_put_uint8(writer, record->version_minor);

   return written;
}

static gboolean read_record_header(FpiByteReader *reader, record_t *record)
{
   gboolean read_ok = TRUE;

   read_ok &= fpi_byte_reader_get_uint8(reader, &record->type);
   read_ok &= fpi_byte_reader_get_uint8(reader, &record->version_major);
   read_ok &= fpi_byte_reader_get_uint8(reader, &record->version_minor);

   return read_ok;
}

static gboolean read_record(const guint8 *serialized_record,
                            const gsize serialized_record_size,
                            record_t *record)
{
   gboolean ret = TRUE;

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, serialized_record, serialized_record_size);
   ret &= read_record_header(&reader, record);
   ret &= fpi_byte_reader_get_uint16_be(&reader, &record->msg_len);
   ret &= fpi_byte_reader_dup_data(&reader, record->msg_len, &record->msg);

   return ret;
}

static gboolean decrypt_record(FpiDeviceSynaTudorMoc *self,
                               record_t *record_to_decrypt, guint8 **ptext,
                               gsize *ptext_len, GError **error)
{
#ifdef TLS_DEBUG
   fp_dbg("Decrypting record msg:");
   fp_dbg_large_hex(record_to_decrypt->msg, record_to_decrypt->msg_len);
#endif

   gboolean ret = TRUE;
   gboolean crypt_initialized = FALSE;

   *ptext_len = 0;

   /* Setup storage for additional data */
   gsize additional_data_size =
       sizeof(self->tls.decrypt_seq_num) + RECORD_HEADER_SIZE;
   guint8 additional_data[additional_data_size];

   /* Split input msg into nonce and crypttext */
   guint64 nonce = FP_READ_UINT64_BE(record_to_decrypt->msg);
   guint8 *ctext = record_to_decrypt->msg + sizeof(nonce);
   gsize ctext_len = record_to_decrypt->msg_len - sizeof(nonce);
   gsize expected_ptext_len = ctext_len - self->tls.tag_size;

   /* create GCM IV = decryption_iv + nonce */
   gnutls_datum_t gcm_iv = {.data = NULL, .size = 0};
   g_assert(self->tls.decryption_iv.size != 0);
   gcm_iv.size = sizeof(nonce) + self->tls.decryption_iv.size;
   gcm_iv.data = g_malloc(gcm_iv.size);
   memcpy(gcm_iv.data, self->tls.decryption_iv.data,
          self->tls.decryption_iv.size);
   FP_WRITE_UINT64_BE(gcm_iv.data + self->tls.decryption_iv.size, nonce);

#ifdef TLS_DEBUG
   fp_dbg("\tdecryption nonce: %lu", nonce);
   fp_dbg("\tdecryption IV:");
   fp_dbg_large_hex(self->tls.decryption_iv.data, self->tls.decryption_iv.size);
   fp_dbg("\tGCM IV:");
   fp_dbg_large_hex(gcm_iv.data, gcm_iv.size);
   fp_dbg("\tdecryption key:");
   fp_dbg_large_hex(self->tls.decryption_key.data,
                    self->tls.decryption_key.size);
#endif

   /* Initialize GCM cipher */
   g_assert(self->tls.cipher_alg == GNUTLS_CIPHER_AES_256_GCM);
   gnutls_aead_cipher_hd_t aead_hd;
   GNUTLS_CHECK(gnutls_aead_cipher_init(&aead_hd, self->tls.cipher_alg,
                                        &self->tls.decryption_key));
   crypt_initialized = TRUE;

   /* Setup additional data
    * = decryption_seq_num (8) + record_header (5) */
   FpiByteWriter writer;
   gboolean written = TRUE;
   fpi_byte_writer_init_with_data(&writer, additional_data,
                                  additional_data_size, FALSE);
   written &= fpi_byte_writer_put_uint64_be(&writer, self->tls.decrypt_seq_num);
   written &= write_record_header(&writer, record_to_decrypt);
   written &= fpi_byte_writer_put_uint16_be(&writer, expected_ptext_len);
   /* NOTE: this should have no way of failing */
   WRITTEN_CHECK(written);

   /* Allocate for result */
   gsize allocated_for_ptext = expected_ptext_len;
   *ptext = g_malloc(allocated_for_ptext);

#ifdef TLS_DEBUG
   fp_dbg("Decryption - auth data:");
   fp_dbg_large_hex(additional_data, additional_data_size);
#endif

   /* Decrypt text */
   GNUTLS_CHECK(gnutls_aead_cipher_decrypt(
       aead_hd, gcm_iv.data, gcm_iv.size, additional_data, additional_data_size,
       self->tls.tag_size, ctext, ctext_len, *ptext, &allocated_for_ptext));

   /* Set decrypted text size (decryption may be shorter) */
   *ptext_len = allocated_for_ptext;

   self->tls.decrypt_seq_num += 1;

#ifdef TLS_DEBUG
   fp_dbg("Decrypted:");
   fp_dbg_large_hex(*ptext, *ptext_len);
#endif

error:
   if (crypt_initialized) {
      gnutls_aead_cipher_deinit(aead_hd);
   }
   if (!ret && *ptext != NULL) {
      g_free(*ptext);
      *ptext = NULL;
   }
   if (gcm_iv.data != NULL) {
      g_free(gcm_iv.data);
   }

   return ret;
}

static void log_tls_alert_msg(const guint alert_level,
                              const guint alert_description)
{
   const char *alert_level_msg =
       alert_level == GNUTLS_AL_WARNING ? "WARNING" : "FATAL";
   fp_err("Received TLS alert level %d aka %s with description: %u aka %s",
          alert_level, alert_level_msg, alert_description,
          gnutls_alert_get_name(alert_description));
}

static gboolean tls_prf(const gnutls_datum_t secret,
                        gnutls_mac_algorithm_t mac_algo, const char *label,
                        const guint8 *seed, gsize seed_len, guint8 **output,
                        gsize output_len, GError **error)
{
   /* Validate input parameters */
   g_return_val_if_fail(label != NULL, FALSE);
   g_return_val_if_fail(seed != NULL, FALSE);
   g_return_val_if_fail(output != NULL, FALSE);
   g_return_val_if_fail(output_len > 0, FALSE);

   gboolean ret = TRUE;

   const gsize buf_size = 128;
   const gsize hmac_size = gnutls_hmac_get_len(mac_algo);

   g_autofree guint8 *input = NULL;
   *output = NULL;
   g_autofree guint8 *to_digest = NULL;

   /* prepare buffers */
   guint8 A[hmac_size];
   guint8 buf_digested[hmac_size];

   gsize label_len = strlen(label);
   g_assert(label_len > 0);

   /* Check if seed and label fit */
   if (hmac_size + label_len + seed_len > buf_size) {
      fp_err("Input arguments too large in %s", __FUNCTION__);
      return FALSE;
   }

   /* Allocate output buffer */
   *output = g_malloc0(output_len);

   /* prepare input = label + seed */
   gsize input_len = label_len + seed_len;
   input = g_malloc0(input_len);
   /* note the ascii encoding */
   memcpy(input, label, label_len);
   memcpy(input + label_len, seed, seed_len);

   /* prepare to_digest buffer */
   gsize to_digest_len = sizeof(A) + input_len;
   to_digest = g_malloc(to_digest_len);

   /* Initialize A to the first input */
   memset(A, 0, sizeof(A));

   /* update A with first hash */
   GNUTLS_CHECK(gnutls_hmac_fast(mac_algo, secret.data, secret.size, input,
                                 input_len, A));

   gsize output_offset = 0;
   while (output_offset < output_len) {

      /* Prepare to_digest buffer */
      memcpy(to_digest, A, sizeof(A));
      memcpy(to_digest + sizeof(A), input, input_len);

      /* update output */
      GNUTLS_CHECK(gnutls_hmac_fast(mac_algo, secret.data, secret.size,
                                    to_digest, to_digest_len, buf_digested));

      gsize remains_to_write = output_len - output_offset;
      gsize to_write =
          remains_to_write < hmac_size ? remains_to_write : hmac_size;
      g_assert(output_offset + to_write <= output_len);
      memcpy(*output + output_offset, buf_digested, to_write);
      output_offset += to_write;

      /* update A */
      GNUTLS_CHECK(gnutls_hmac_fast(mac_algo, secret.data, secret.size, A,
                                    sizeof(A), A));
   }

error:
   if ((!ret) && (*output != NULL)) {
      g_free(*output);
      *output = NULL;
   }
   return ret;
}

static gboolean check_server_finished_verify_data(FpiDeviceSynaTudorMoc *self,
                                                  FpiByteReader *reader,
                                                  gsize recv_verify_data_size,
                                                  gboolean *is_correct,
                                                  GError **error)
{
   gboolean ret = TRUE;
   *is_correct = FALSE;
   const gnutls_digest_algorithm_t hash_algo = GNUTLS_DIG_SHA256;
   const guint hash_size = gnutls_hash_get_len(hash_algo);
   guint8 sent_messages_hash[hash_size];

   g_autofree guint8 *verify_data = NULL;
   g_autofree guint8 *recv_verify_data = NULL;

   /* sizes should match */
   if (recv_verify_data_size != VERIFY_DATA_SIZE) {
      fp_err("Received server finished with unexpected length: %lu, while "
             "expected was %d",
             recv_verify_data_size, VERIFY_DATA_SIZE);
      return ret;
   }

   fpi_byte_reader_dup_data(reader, VERIFY_DATA_SIZE, &recv_verify_data);

#ifdef TLS_DEBUG
   fp_dbg("Server finished sent messages:");
   fp_dbg_large_hex(self->tls.sent_handshake_msgs,
                    self->tls.sent_handshake_msgs_size);
#endif

   GNUTLS_CHECK(gnutls_hash_fast(hash_algo, self->tls.sent_handshake_msgs,
                                 self->tls.sent_handshake_msgs_size,
                                 sent_messages_hash));
#ifdef TLS_DEBUG
   fp_dbg("Handshake finished sent messages hash:");
   fp_dbg_large_hex(sent_messages_hash, sizeof(sent_messages_hash));
#endif

   BOOL_CHECK(tls_prf(self->tls.master_secret, self->tls.mac_algo,
                      "server finished", sent_messages_hash, hash_size,
                      &verify_data, VERIFY_DATA_SIZE, error));

#ifdef TLS_DEBUG
   fp_dbg("tls prf server finished output:");
   fp_dbg_large_hex(verify_data, VERIFY_DATA_SIZE);
#endif

   if (recv_verify_data_size >= VERIFY_DATA_SIZE &&
       0 == memcmp(verify_data, recv_verify_data, VERIFY_DATA_SIZE)) {
      *is_correct = TRUE;
      fp_dbg("Server finished verify data match");
   } else {
      fp_err("Server finished verify data do NOT match");
      fp_err("Got:");
      fp_dbg_large_hex(recv_verify_data, recv_verify_data_size);
      fp_err("Expected:");
      fp_dbg_large_hex(verify_data, VERIFY_DATA_SIZE);

      self->tls.handshake_state = TLS_HS_STATE_ALERT;
      self->tls.alert_level = GNUTLS_AL_FATAL;
      self->tls.alert_desc = GNUTLS_A_ILLEGAL_PARAMETER;
   }

error:
   return ret;
}

gboolean parse_certificate(const guint8 *data, const gsize len, cert_t *cert)
{
   if (len != CERTIFICATE_SIZE) {
      fp_err("Received certificate with incorrect length: %lu", len);
      return FALSE;
   }

   const guint8 *to_copy = NULL;

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, data, len);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &cert->magic);
   g_assert(cert->magic == 0x5F3F);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &cert->curve);
   g_assert(cert->curve == 23);

   /* memcpy as we use variable length arrays for storage */
   g_assert(sizeof(cert->pubkey_x) == CERTIFICATE_KEY_SIZE);
   read_ok &=
       fpi_byte_reader_get_data(&reader, sizeof(cert->pubkey_x), &to_copy);
   if (read_ok) {
      memcpy(cert->pubkey_x, to_copy, sizeof(cert->pubkey_x));
   }

   g_assert(sizeof(cert->pubkey_y) == CERTIFICATE_KEY_SIZE);
   read_ok &=
       fpi_byte_reader_get_data(&reader, sizeof(cert->pubkey_y), &to_copy);
   if (read_ok) {
      memcpy(cert->pubkey_y, to_copy, sizeof(cert->pubkey_y));
   }

   read_ok &= fpi_byte_reader_get_uint8(&reader, &cert->padding);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &cert->cert_type);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &cert->sign_size);
   read_ok &=
       fpi_byte_reader_get_data(&reader, sizeof(cert->sign_data), &to_copy);
   if (read_ok) {
      memcpy(cert->sign_data, to_copy, sizeof(cert->sign_data));
   }

   /* check for completion */
   if (read_ok) {
      g_assert(fpi_byte_reader_get_pos(&reader) == CERTIFICATE_SIZE);
   }

   return read_ok;
}

static gboolean get_client_hello_record(FpiDeviceSynaTudorMoc *self,
                                        hello_t *client_hello, record_t *record)
{
   g_return_val_if_fail(client_hello != NULL, FALSE);
   g_return_val_if_fail(record != NULL, FALSE);

   record->type = RECORD_TYPE_HANDSHAKE;
   record->version_major = self->tls.version_major;
   record->version_minor = self->tls.version_minor;

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init(&writer);

   /* write message type - client hello*/
   written &= fpi_byte_writer_put_uint8(&writer, HS_CLIENT_HELLO);
   /* write 0 to client hello data length and save offset for later */
   guint total_len_offset = fpi_byte_writer_get_pos(&writer);
   written &= fpi_byte_writer_put_uint24_be(&writer, 0);

   /* write major and minor client version */
   written &= fpi_byte_writer_put_uint8(&writer, client_hello->version_major);
   written &= fpi_byte_writer_put_uint8(&writer, client_hello->version_minor);

   /* write current time  and client random */
   written &=
       fpi_byte_writer_put_uint32_be(&writer, client_hello->current_timestamp);
   written &= fpi_byte_writer_put_data(&writer, client_hello->random,
                                       sizeof(client_hello->random));

   /* write session id */
   written &= fpi_byte_writer_put_uint8(&writer, SESSION_ID_LEN);
   written &= fpi_byte_writer_put_data(&writer, client_hello->session_id,
                                       SESSION_ID_LEN);

   /* write cipher cuites */
   guint16 cipher_suite_id_array_total_len =
       client_hello->cipher_suit_cnt * sizeof(guint16);
   written &=
       fpi_byte_writer_put_uint16_be(&writer, cipher_suite_id_array_total_len);
   for (int i = 0; i < client_hello->cipher_suit_cnt; ++i) {
      written &= fpi_byte_writer_put_uint16_be(
          &writer, client_hello->cipher_suits[i].id);
   }

   /* write compression methods - these are unsupported, so write 0
    * NOTE: The windows driver does not advertise the NULL compression method.
    */
   written &= fpi_byte_writer_put_uint8(&writer, 0);

   /* write extensions
    * NOTE: The developers did not give the extensions field a length value. */
   for (int i = 0; i < client_hello->extension_cnt; ++i) {
      written &= fpi_byte_writer_put_uint16_be(&writer,
                                               client_hello->extensions[i].id);
      written &= fpi_byte_writer_put_uint16_be(&writer,
                                               client_hello->extensions[i].len);
      written &=
          fpi_byte_writer_put_data(&writer, client_hello->extensions[i].data,
                                   client_hello->extensions[i].len);
   }

   if (!written) {
      fp_err("Error occured while serializing client hello");
      goto error;
   } else {
      guint total_len = fpi_byte_writer_get_pos(&writer);
      record->msg_len = total_len;
      record->msg = fpi_byte_writer_reset_and_get_data(&writer);

      /* write msg_len to header */
      const guint handshake_header_len = 4;
      FP_WRITE_UINT24_BE(&record->msg[total_len_offset],
                         total_len - handshake_header_len);
   }

   return TRUE;
error:
   return FALSE;
}

gboolean get_remote_tls_status(FpiDeviceSynaTudorMoc *self, gboolean *status,
                               GError **error)
{
   gboolean ret = TRUE;
   g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new(FP_DEVICE(self));

   fpi_usb_transfer_fill_control(
       transfer, G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
       G_USB_DEVICE_REQUEST_TYPE_VENDOR, G_USB_DEVICE_RECIPIENT_DEVICE,
       REQUEST_TLS_SESSION_STATUS, 0, 0, TLS_SESSION_STATUS_DATA_RESP_LEN);

   transfer->short_is_error = TRUE;
   fpi_usb_transfer_submit_sync(transfer, TLS_SESSION_STATUS_TIMEOUT_MS, error);

   if (*error) {
      goto error;
   }

   g_assert(transfer->actual_length >= 1);

   *status = FP_READ_UINT8(transfer->buffer) != 0;
   fp_dbg("Remote TLS session status: %s",
          *status ? "established" : "not established");

error:
   return ret;
}

static void update_handshake_messages_data(FpiDeviceSynaTudorMoc *self,
                                           const guint8 *data, const gsize size)
{
   /* NOTE: per decompiled code do not update with *finished messages* */
   gsize remaining_alloc_size = self->tls.sent_handshake_msgs_alloc_size -
                                self->tls.sent_handshake_msgs_size;

   if (remaining_alloc_size <= size) {
      gsize realloc_size =
          (self->tls.sent_handshake_msgs_alloc_size + size) * 2;
      self->tls.sent_handshake_msgs =
          g_realloc(self->tls.sent_handshake_msgs, realloc_size);
      self->tls.sent_handshake_msgs_alloc_size = realloc_size;
   }

   memcpy(&self->tls.sent_handshake_msgs[self->tls.sent_handshake_msgs_size],
          data, size);
   self->tls.sent_handshake_msgs_size += size;

#ifdef TLS_DEBUG
   fp_dbg("sent messages:");
   fp_dbg_large_hex(self->tls.sent_handshake_msgs,
                    self->tls.sent_handshake_msgs_size);
#endif
}

static void update_handshake_messages_data_record(FpiDeviceSynaTudorMoc *self,
                                                  const record_t *rec)
{
   /* windows driver does not update with HS_FINISHED messages */
   if (rec->msg[0] != HS_FINISHED) {
      update_handshake_messages_data(self, rec->msg, rec->msg_len);
   }
}

static gboolean send_tls(FpiDeviceSynaTudorMoc *self,
                         const record_t *send_records,
                         const guint send_record_cnt, guint8 **recv_data,
                         gsize *recv_size, gboolean with_hs_header,
                         GError **error)
{
   gboolean ret = TRUE;
   /* +3 is the padding? */
   *recv_size = 256;

   guint8 *send_data = NULL;

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init(&writer);
   if (with_hs_header) {
      /* write command ID */
      written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_TLS_DATA);
      /* some padding? */
      written &= fpi_byte_writer_put_uint24_le(&writer, 0);
   }

   for (int i = 0; i < send_record_cnt; ++i) {
      /* write record header */
      written &= write_record_header(&writer, &send_records[i]);
      written &=
          fpi_byte_writer_put_uint16_be(&writer, send_records[i].msg_len);
      /* write record data */
      written &= fpi_byte_writer_put_data(&writer, send_records[i].msg,
                                          send_records[i].msg_len);
   }

   WRITTEN_CHECK(written);

   gsize send_size = fpi_byte_writer_get_pos(&writer);
   send_data = fpi_byte_writer_reset_and_get_data(&writer);

   /* do not check status, as it is not present */
   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, recv_data,
                                       recv_size, FALSE, error));

error:
   if (send_data != NULL) {
      g_free(send_data);
   }
   if (!ret && recv_data != NULL) {
      g_free(*recv_data);
      *recv_data = NULL;
   }
   return ret;
}

static gboolean init_client_hello(FpiDeviceSynaTudorMoc *self,
                                  hello_t *client_hello)
{

   client_hello->version_major = self->tls.version_major,
   client_hello->version_minor = self->tls.version_minor;

   GDateTime *datetime = g_date_time_new_now_utc();
   client_hello->current_timestamp = g_date_time_to_unix(datetime);
   g_date_time_unref(datetime);

   /* generate client random */
   GRand *rand = g_rand_new();
   for (int i = 0; i < sizeof(client_hello->random); ++i) {
      client_hello->random[i] = g_rand_int_range(rand, 0, 255);
   }
   g_rand_free(rand);

   /* store client random*/
   FP_WRITE_UINT32_BE(self->tls.client_random, client_hello->current_timestamp);
   memcpy(self->tls.client_random + sizeof(client_hello->current_timestamp),
          client_hello->random, sizeof(client_hello->random));

#ifdef TLS_DEBUG
   fp_dbg("Client random is:");
   guint8 serialized_timestamp[sizeof(client_hello->current_timestamp)];
   FP_WRITE_UINT32_BE(serialized_timestamp, client_hello->current_timestamp);
   fp_dbg("\ttimestamp:");
   fp_dbg_large_hex(serialized_timestamp,
                    sizeof(client_hello->current_timestamp));
   fp_dbg("\trand:");
   fp_dbg_large_hex(client_hello->random, sizeof(client_hello->random));
#endif

   /* copy session id from self */
   memcpy(&client_hello->session_id, self->tls.session_id, SESSION_ID_LEN);

   /* only ciphersuite which seemed to work is 0xC02E
    * -> for now hardcode everything per this */
   client_hello->cipher_suit_cnt = 1;
   client_hello->cipher_suits = &tls_ecdh_ecdsa_with_aes_256_gcm_sha384;

   client_hello->extension_cnt = 2;
   client_hello->extensions = g_new(extension_t, client_hello->extension_cnt);
   memcpy(&client_hello->extensions[0], &supported_groups, sizeof(extension_t));
   memcpy(&client_hello->extensions[1], &ec_point_formats, sizeof(extension_t));

   return TRUE;
   /* error:
      if (client_hello->extensions != NULL) {
         g_free(client_hello->extensions);
      }
      return FALSE; */
}

static gboolean parse_and_process_server_hello(FpiDeviceSynaTudorMoc *self,
                                               FpiByteReader *reader,
                                               const guint32 read_len,
                                               GError **error)
{
   g_assert(self != NULL && reader != NULL);

   gboolean ret = TRUE;

   guint32 read_start_pos = fpi_byte_reader_get_pos(reader);
   const guint8 *to_copy = NULL;

   guint8 version_major;
   ret &= fpi_byte_reader_get_uint8(reader, &version_major);
   guint8 version_minor;
   ret &= fpi_byte_reader_get_uint8(reader, &version_minor);

   /* version check copied from decompiled code */
   if (ret && ((version_major != 3) || ((version_minor & 3) != 3))) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Server hello - major or minor version is invalid");
      ret = FALSE;
      goto error;
   }

   /* read current time and server random */
   ret &= fpi_byte_reader_get_data(reader, sizeof(self->tls.server_random),
                                   &to_copy);
   if (ret) {
      memcpy(&self->tls.server_random, to_copy,
             sizeof(self->tls.server_random));
#ifdef TLS_DEBUG
      fp_dbg("received server_random:");
      fp_dbg_large_hex(self->tls.server_random,
                       sizeof(self->tls.server_random));
#endif
   }

   /* read session id */
   guint8 session_id_len = 0;
   ret &= fpi_byte_reader_get_uint8(reader, &session_id_len);
   if (ret && session_id_len != SESSION_ID_LEN) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Invalid session_id length: expected: %d, got: %d", SESSION_ID_LEN,
          session_id_len);
   }
   ret &= fpi_byte_reader_get_data(reader, SESSION_ID_LEN, &to_copy);
   if (ret) {
      memcpy(self->tls.session_id, to_copy, SESSION_ID_LEN);
   }

   /* read cipher cuites */
   ret &= fpi_byte_reader_get_uint16_be(reader, &self->tls.ciphersuit);
   if (self->tls.ciphersuit != tls_ecdh_ecdsa_with_aes_256_gcm_sha384.id) {
      fp_err(
          "Ciphersuite requested by server with id: 0x%04x is not implemented",
          self->tls.ciphersuit);
      ret = FALSE;
   }

   self->tls.mac_algo = tls_ecdh_ecdsa_with_aes_256_gcm_sha384.mac_algo;
   /* read compression method */
   ret &= fpi_byte_reader_get_uint8(reader, &self->tls.compression_method);

   /* nothing else seems to be sent*/

   guint32 read_end_pos = fpi_byte_reader_get_pos(reader);
   if (read_end_pos - read_start_pos != read_len) {
      ret = FALSE;
      fp_err("Error occured while reading server hello");
      fp_err("\tstarted at: %d, ended at: %d, expected end: %d", read_start_pos,
             read_end_pos, read_start_pos + read_len);
   }

error:
   return ret;
}

static gboolean
parse_and_process_certificate_request(FpiDeviceSynaTudorMoc *self,
                                      FpiByteReader *reader,
                                      const guint msg_len, GError **error)
{
   gboolean ret = TRUE;

   if (msg_len != 4) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Unexpected msg_len of certificate request received: %d", msg_len);
      ret = FALSE;
      goto error;
   }

   guint8 num_requested_certs = 0;
   ret &= fpi_byte_reader_get_uint8(reader, &num_requested_certs);

   if (ret && num_requested_certs != 1) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Requested an unimplemented number of certificates: %d",
          num_requested_certs);
      ret = FALSE;
      goto error;
   }

   guint8 certificate_type = 0;
   ret &= fpi_byte_reader_get_uint8(reader, &certificate_type);
   /* skip over garbage bytes */
   ret &= fpi_byte_reader_skip(reader, 2);

   READ_OK_CHECK(ret);

   fp_dbg("Requested certificate of type: 0x%x", certificate_type);
   self->tls.requested_cert = certificate_type;
   self->tls.handshake_state = TLS_HS_STATE_END;

error:
   return ret;
}

static gboolean parse_and_process_hs_finished(FpiDeviceSynaTudorMoc *self,
                                              FpiByteReader *reader,
                                              const guint msg_len,
                                              GError **error)
{
   gboolean ret = TRUE;

   if (self->tls.handshake_state != TLS_HS_STATE_END) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Unexpected recieval of handshake finished message - "
          "handshake state is %d",
          self->tls.handshake_state);
      ret = FALSE;
   }
   gboolean verify_matches = FALSE;
   BOOL_CHECK(check_server_finished_verify_data(self, reader, msg_len,
                                                &verify_matches, error));
   if (!verify_matches) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Server verify message does not match the one expected");
      ret = FALSE;
      goto error;
   }
   fp_dbg("Server verify message matches");
   self->tls.established = TRUE;
   self->tls.handshake_state = TLS_HS_STATE_FINISHED;

error:
   return ret;
}

static gboolean parse_and_process_handshake_record(FpiDeviceSynaTudorMoc *self,
                                                   record_t *record,
                                                   GError **error)
{
   gboolean ret = TRUE;
   FpiByteReader reader;
   gboolean read_ok = TRUE;
   fpi_byte_reader_init(&reader, record->msg, record->msg_len);

   gboolean cont = TRUE;
   while (cont && (fpi_byte_reader_get_remaining(&reader) != 0)) {
      /* parse msg header */
      guint8 msg_type = 0;
      read_ok &= fpi_byte_reader_get_uint8(&reader, &msg_type);
      guint32 msg_len = 0;
      read_ok &= fpi_byte_reader_get_uint24_be(&reader, &msg_len);
      fp_dbg("Received record of type 0x%02x and length of %d", msg_type,
             msg_len);
      if (!read_ok) {
         fp_err("Error while reading message header from record");
         goto error;
      }

      switch (msg_type) {
      case HS_SERVER_HELLO:
         fp_dbg("received server hello");
         BOOL_CHECK(
             parse_and_process_server_hello(self, &reader, msg_len, error));
         break;
      case HS_CERTIFICATE_REQUEST:
         fp_dbg("received certificate request");
         BOOL_CHECK(parse_and_process_certificate_request(self, &reader,
                                                          msg_len, error));
         break;

      case HS_SERVER_HELLO_DONE:
         fp_dbg("received server hello done");
         if (self->tls.handshake_state != TLS_HS_STATE_END) {
            *error = set_and_report_error(
                FP_DEVICE_ERROR_GENERAL,
                "invalied handshake_state at start of HS_SERVER_HELLO_DONE: %d",
                self->tls.handshake_state);
            self->tls.handshake_state = TLS_HS_STATE_END;
            ret = FALSE;
         }
         cont = FALSE;
         break;

      case HS_FINISHED:
         fp_dbg("received handshake finished");
         BOOL_CHECK(
             parse_and_process_hs_finished(self, &reader, msg_len, error));
         cont = FALSE;
         break;

      default:
         fp_err("Received unimplemented msg type: %d", msg_type);
         *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                       "Received unimplemented msg type: %d",
                                       msg_type);
         ret = FALSE;
      }

      READ_OK_CHECK(read_ok);
   }

error:
   return ret;
}

static gboolean record_version_matches_clients(FpiDeviceSynaTudorMoc *self,
                                               record_t *record)
{
   if (record->version_major != self->tls.version_major ||
       record->version_minor != self->tls.version_minor) {
      fp_err("Invalid received record version: %d.%d, expected: %d.%d",
             record->version_major, record->version_minor,
             self->tls.version_major, self->tls.version_minor);
      self->tls.handshake_state = TLS_HS_STATE_ALERT;
      self->tls.alert_level = GNUTLS_AL_WARNING;
      self->tls.alert_desc = GNUTLS_A_ILLEGAL_PARAMETER;
      return FALSE;
   }
   return TRUE;
}

static gboolean parse_and_process_records(FpiDeviceSynaTudorMoc *self,
                                          guint8 *data, gsize data_len,
                                          GError **error)
{
   FpiByteReader reader;
   gboolean read_ok = TRUE;
   gboolean ret = TRUE;
   fpi_byte_reader_init(&reader, data, data_len);

   record_t record = {.msg = NULL};
   while ((fpi_byte_reader_get_remaining(&reader) != 0) && read_ok) {
      record.msg = NULL;
      /* parse record header */
      read_ok &= fpi_byte_reader_get_uint8(&reader, &record.type);
      read_ok &= fpi_byte_reader_get_uint8(&reader, &record.version_major);
      read_ok &= fpi_byte_reader_get_uint8(&reader, &record.version_minor);
      read_ok &= fpi_byte_reader_get_uint16_be(&reader, &record.msg_len);
      if (read_ok) {
         read_ok &=
             fpi_byte_reader_dup_data(&reader, record.msg_len, &record.msg);
      }
      READ_OK_CHECK(read_ok);

      if (self->tls.remote_sends_encrypted) {
         guint8 *ptext = NULL;
         gsize ptext_size = 0;
         BOOL_CHECK(decrypt_record(self, &record, &ptext, &ptext_size, error));
         g_free(record.msg);
         record.msg = ptext;
         record.msg_len = ptext_size;
      }

      fp_dbg("%s received record:", __FUNCTION__);
      fp_dbg("\tMsg type: 0x%x", record.type);
      fp_dbg("\tVersion: %d.%d", record.version_major, record.version_minor);
      fp_dbg("\tData len: %d", record.msg_len);

      if (!record_version_matches_clients(self, &record)) {
         goto error;
      }

      if (record.msg_len == 0) {
         fp_err("Received record with zero message length");
         self->tls.alert_level = GNUTLS_AL_WARNING;
         self->tls.alert_desc = GNUTLS_A_ILLEGAL_PARAMETER;
         self->tls.handshake_state = TLS_HS_STATE_ALERT;
      }

      switch (record.type) {
      case RECORD_TYPE_CHANGE_CIPHER_SPEC:
         /* Expected is one number */
         if (record.msg_len != 1) {
            fp_err("Invalid CHANGE_CIPHER_SPEC message received");
            self->tls.alert_level = GNUTLS_AL_WARNING;
            self->tls.alert_desc = GNUTLS_A_ILLEGAL_PARAMETER;
            self->tls.handshake_state = TLS_HS_STATE_ALERT;
         } else {
            fp_dbg("Change cipher spec received - enabling remote decryption");
            self->tls.remote_sends_encrypted = TRUE;
         }
         break;

      case RECORD_TYPE_HANDSHAKE:
         update_handshake_messages_data_record(self, &record);
         BOOL_CHECK(parse_and_process_handshake_record(self, &record, error));
         break;

      case RECORD_TYPE_ALERT:;
         if (record.msg_len != 2) {
            fp_err("Invalid length of received TLS alert message");
            self->tls.alert_level = GNUTLS_AL_WARNING;
            self->tls.alert_desc = GNUTLS_A_ILLEGAL_PARAMETER;
            self->tls.handshake_state = TLS_HS_STATE_ALERT;
            goto error;
         }

         guint8 alert_level = record.msg[0];
         guint8 alert_description = record.msg[1];

         if (alert_level == GNUTLS_AL_WARNING &&
             alert_description == GNUTLS_A_CLOSE_NOTIFY) {
            fp_dbg("Remote confirmed TLS session close");
            self->tls.remote_sends_encrypted = FALSE;
            self->tls.established = FALSE;
         } else if (alert_level != 0 &&
                    alert_description != GNUTLS_A_BAD_CERTIFICATE) {
            fp_err("Host has bad certificate - need to re-pair the sensor");
            self->tls.remote_sends_encrypted = FALSE;
            self->tls.established = FALSE;
         } else {
            log_tls_alert_msg(alert_level, alert_description);
         }

         self->tls.handshake_state = TLS_HS_STATE_ALERT;
         goto error;
         break;

      case RECORD_TYPE_APPLICATION_DATA:
         fp_err("Unexpected application data message received");
         self->tls.alert_level = GNUTLS_AL_WARNING;
         self->tls.alert_desc = GNUTLS_A_UNEXPECTED_MESSAGE;
         self->tls.handshake_state = TLS_HS_STATE_ALERT;
         goto error;
         break;

      default:
         fp_err("Got unimplemented record type: %d", record.type);
         self->tls.alert_level = GNUTLS_AL_WARNING;
         self->tls.alert_desc = GNUTLS_A_UNEXPECTED_MESSAGE;
         self->tls.handshake_state = TLS_HS_STATE_ALERT;
         goto error;
         break;
         goto error;
      }
      if (record.msg != NULL) {
         g_free(record.msg);
         record.msg = NULL;
      }
   }

error:
   if (record.msg != NULL) {
      g_free(record.msg);
   }
   return ret;
}

static gboolean append_client_certificate(FpiDeviceSynaTudorMoc *self,
                                          FpiByteWriter *writer)
{
   gboolean written = TRUE;

   /* add header */
   written &= fpi_byte_writer_put_uint8(writer, HS_CERTIFICATE);
   /* 8 = 2*3 (for size) + 2 (for padding?) */
   guint32 cert_msg_size = 8 + sizeof(cert_t);
   written &= fpi_byte_writer_put_uint24_be(writer, cert_msg_size);

   /* add size twice for some reason */
   written &= fpi_byte_writer_put_uint24_be(writer, CERTIFICATE_SIZE);
   written &= fpi_byte_writer_put_uint24_be(writer, CERTIFICATE_SIZE);
   /* add the padding? */
   written &= fpi_byte_writer_put_uint16_be(writer, 0);

   /* add the certificate itself*/
   written &= fpi_byte_writer_put_data(
       writer, (guint8 *)&self->pairing_data.host_cert, CERTIFICATE_SIZE);

   return written;
}

static gboolean append_client_key_exchange_to_record(
    FpiByteWriter *writer, const gnutls_privkey_t *privkey, GError **error)
{
   gboolean ret = TRUE;

   /* add header */
   ret &= fpi_byte_writer_put_uint8(writer, HS_CLIENT_KEY_EXCHANGE);
   /* format + sizeof(x) + sizeof(y) */
   guint32 msg_size = 1 + 32 + 32;
   ret &= fpi_byte_writer_put_uint24_be(writer, msg_size);

   /* get public key */
   gnutls_pubkey_t pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&pubkey));

   GNUTLS_CHECK(gnutls_pubkey_import_privkey(pubkey, *privkey,
                                             GNUTLS_KEY_DIGITAL_SIGNATURE, 0));

   gnutls_datum_t x;
   gnutls_datum_t y;
   GNUTLS_CHECK(gnutls_pubkey_export_ecc_raw(pubkey, NULL, &x, &y));
   gnutls_pubkey_deinit(pubkey);

#ifdef TLS_DEBUG
   fp_dbg("exported pubkey");
   fp_dbg("\tx");
   fp_dbg_large_hex(x.data, x.size);
   fp_dbg("\ty");
   fp_dbg_large_hex(y.data, y.size);
#endif

   /* uncompressed format */
   guint x_offset = x.size - ECC_KEY_SIZE;
   guint y_offset = y.size - ECC_KEY_SIZE;

#ifdef TLS_DEBUG
   if (x_offset != 0) {
      fp_dbg("x point data before:");
      fp_dbg_large_hex(x.data, x.size);
      fp_dbg("x point data after:");
      fp_dbg_large_hex(x.data + x_offset, ECC_KEY_SIZE);
      fp_dbg("");
   }
   if (y_offset != 0) {
      fp_dbg("y size if %d > ECC_KEY_SIZE -> offset = %d", y.size, y_offset);
      fp_dbg("y point data before:");
      fp_dbg_large_hex(y.data, y.size);
      fp_dbg("y point data after:");
      fp_dbg_large_hex(y.data + y_offset, ECC_KEY_SIZE);
      fp_dbg("");
   }
#endif

   ret &= fpi_byte_writer_put_uint8(writer, 0x4);
   ret &= fpi_byte_writer_put_data(writer, x.data + x_offset, ECC_KEY_SIZE);
   ret &= fpi_byte_writer_put_data(writer, y.data + y_offset, ECC_KEY_SIZE);

error:
   if (x.data != NULL) {
      g_free(x.data);
   }
   if (y.data != NULL) {
      g_free(y.data);
   }

   return ret;
}

static gboolean append_certificate_verify_to_record(FpiDeviceSynaTudorMoc *self,
                                                    FpiByteWriter *writer,
                                                    GError **error)
{
   gboolean ret = TRUE;
   const gnutls_digest_algorithm_t hash_algo = GNUTLS_DIG_SHA256;
   const guint hash_size = gnutls_hash_get_len(hash_algo);
   guint8 sent_messages_hash[hash_size];
   gnutls_datum_t sent_messages_hash_datum = {.data = sent_messages_hash,
                                              .size = hash_size};
   gnutls_datum_t signature = {.data = NULL, .size = 0};

#ifdef TLS_DEBUG
   fp_dbg("Messages to certificate veify");
   fp_dbg_large_hex(self->tls.sent_handshake_msgs,
                    self->tls.sent_handshake_msgs_size);
#endif

   GNUTLS_CHECK(gnutls_hash_fast(
       GNUTLS_DIG_SHA256, self->tls.sent_handshake_msgs,
       self->tls.sent_handshake_msgs_size, &sent_messages_hash));

#ifdef TLS_DEBUG
   fp_dbg("Siging hash:");
   fp_dbg_large_hex(sent_messages_hash, hash_size);
#endif

   GNUTLS_CHECK(gnutls_privkey_sign_hash2(
       self->pairing_data.private_key, GNUTLS_SIGN_ECDSA_SHA256, 0,
       &sent_messages_hash_datum, &signature));

#ifdef TLS_DEBUG
   fp_dbg("Signature:");
   fp_dbg_large_hex(signature.data, signature.size);
#endif

   /* add header */
   ret &= fpi_byte_writer_put_uint8(writer, HS_CERTIFICATE_VERIFY);
   ret &= fpi_byte_writer_put_uint24_be(writer, signature.size);
   ret &= fpi_byte_writer_put_data(writer, signature.data, signature.size);

error:
   if (signature.data != NULL) {
      g_free(signature.data);
   }
   return ret;
}

static gboolean encrypt_record(FpiDeviceSynaTudorMoc *self,
                               record_t *record_to_encrypt, guint8 **ctext,
                               gsize *ctext_len, GError **error)
{
#ifdef TLS_DEBUG
   fp_dbg("Encrypting record msg:");
   fp_dbg_large_hex(record_to_encrypt->msg, record_to_encrypt->msg_len);
#endif

   gboolean ret = TRUE;
   gboolean crypt_initialized = FALSE;

   gnutls_datum_t gcm_iv = {.data = NULL, .size = 0};

   /* Setup storage for additional data */
   gsize additional_data_size =
       sizeof(self->tls.encrypt_seq_num) + RECORD_HEADER_SIZE;
   guint8 additional_data[additional_data_size];

   /* create random nonce */
   guint64 nonce;
   GNUTLS_CHECK(gnutls_rnd(GNUTLS_RND_NONCE, &nonce, sizeof(nonce)));

   /* create GCM IV = encryption_iv + nonce */
   g_assert(self->tls.encryption_iv.size != 0);
   gcm_iv.size = sizeof(nonce) + self->tls.encryption_iv.size;
   gcm_iv.data = g_malloc(gcm_iv.size);
   memcpy(gcm_iv.data, self->tls.encryption_iv.data,
          self->tls.encryption_iv.size);
   FP_WRITE_UINT64_BE(gcm_iv.data + self->tls.encryption_iv.size, nonce);

#ifdef TLS_DEBUG
   fp_dbg("Encryption nonce: %lu", nonce);
   fp_dbg("Encryption IV:");
   fp_dbg_large_hex(self->tls.encryption_iv.data, self->tls.encryption_iv.size);
   fp_dbg("GCM IV:");
   fp_dbg_large_hex(gcm_iv.data, gcm_iv.size);
   fp_dbg("Encryption key:");
   fp_dbg_large_hex(self->tls.encryption_key.data,
                    self->tls.encryption_key.size);
#endif

   /* Initialize GCM cipher */
   g_assert(self->tls.cipher_alg == GNUTLS_CIPHER_AES_256_GCM);
   gnutls_aead_cipher_hd_t aead_hd;
   GNUTLS_CHECK(gnutls_aead_cipher_init(&aead_hd, self->tls.cipher_alg,
                                        &self->tls.encryption_key));
   crypt_initialized = TRUE;

   /* Set additional data
    * = encryption_seq_num (8) + record_header (5) */
   FpiByteWriter writer;
   gboolean written = TRUE;
   fpi_byte_writer_init_with_data(&writer, additional_data,
                                  additional_data_size, FALSE);
   written &= fpi_byte_writer_put_uint64_be(&writer, self->tls.encrypt_seq_num);
   written &= write_record_header(&writer, record_to_encrypt);
   written &=
       fpi_byte_writer_put_uint16_be(&writer, record_to_encrypt->msg_len);
   /* NOTE: this should have no way of failing */
   WRITTEN_CHECK(written);

#ifdef TLS_DEBUG
   fp_dbg("Encryption - auth data:");
   fp_dbg_large_hex(additional_data, additional_data_size);
#endif

   /* Allocate for result */
   gsize allocated_for_ctext = record_to_encrypt->msg_len + self->tls.tag_size;
   gsize to_allocate = sizeof(nonce) + allocated_for_ctext;
   *ctext = g_malloc(to_allocate);

   /* add nonce to output */
   FP_WRITE_UINT64_BE(*ctext, nonce);

   /* Encrypt text */
   GNUTLS_CHECK(gnutls_aead_cipher_encrypt(
       aead_hd, gcm_iv.data, gcm_iv.size, additional_data, additional_data_size,
       self->tls.tag_size, record_to_encrypt->msg, record_to_encrypt->msg_len,
       (*ctext) + sizeof(nonce), &allocated_for_ctext));

   /* Set encrypted text size (encryption may be shorter) */
   *ctext_len = sizeof(nonce) + allocated_for_ctext;

   self->tls.encrypt_seq_num += 1;

#ifdef TLS_DEBUG
   fp_dbg("Encrypted:");
   fp_dbg_large_hex(*ctext, *ctext_len);
#endif

error:
   if (crypt_initialized) {
      gnutls_aead_cipher_deinit(aead_hd);
   }
   if (!ret && *ctext != NULL) {
      g_free(*ctext);
      *ctext = NULL;
   }
   if (gcm_iv.data != NULL) {
      g_free(gcm_iv.data);
   }

   return ret;
}

static gboolean append_encrypted_handshake_finish_to_record(
    FpiDeviceSynaTudorMoc *self, FpiByteWriter *writer, GError **error)
{
   gboolean ret = TRUE;

   const gsize sha256_size = 32;
   const gsize prf_size = 12;
   guint8 sent_messages_sha256[sha256_size];
   g_autofree guint8 *tls_prf_output = NULL;
   g_autofree guint8 *to_encrypt = NULL;
   gsize to_encrypt_size = 0;
   g_autofree guint8 *encrypted = NULL;
   gsize encrypted_size = 0;
   const gsize header_size = 4;

#ifdef TLS_DEBUG
   fp_dbg("Handshake finished sent messages:");
   fp_dbg_large_hex(self->tls.sent_handshake_msgs,
                    self->tls.sent_handshake_msgs_size);
#endif

   GNUTLS_CHECK(gnutls_hash_fast(
       GNUTLS_DIG_SHA256, self->tls.sent_handshake_msgs,
       self->tls.sent_handshake_msgs_size, sent_messages_sha256));
#ifdef TLS_DEBUG
   fp_dbg("Handshake finished sent messages hash:");
   fp_dbg_large_hex(sent_messages_sha256, sizeof(sent_messages_sha256));
#endif

   BOOL_CHECK(tls_prf(self->tls.master_secret, self->tls.mac_algo,
                      "client finished", sent_messages_sha256, sha256_size,
                      &tls_prf_output, prf_size, error));

#ifdef TLS_DEBUG
   fp_dbg("tls prf client finished output:");
   fp_dbg_large_hex(tls_prf_output, prf_size);
#endif

   /* Get data to encrypt */
   to_encrypt_size = header_size + prf_size;
   to_encrypt = g_malloc(to_encrypt_size);
   FpiByteWriter enc_writer;
   fpi_byte_writer_init_with_data(&enc_writer, to_encrypt, to_encrypt_size,
                                  FALSE);
   ret &= fpi_byte_writer_put_uint8(&enc_writer, HS_FINISHED);
   ret &= fpi_byte_writer_put_uint24_be(&enc_writer, prf_size);
   ret &= fpi_byte_writer_put_data(&enc_writer, tls_prf_output, prf_size);

   record_t record_to_encrypt = {
       .type = RECORD_TYPE_HANDSHAKE,
       .version_major = self->tls.version_major,
       .version_minor = self->tls.version_minor,
       .msg_len = to_encrypt_size,
       .msg = to_encrypt,
   };

   BOOL_CHECK(encrypt_record(self, &record_to_encrypt, &encrypted,
                             &encrypted_size, error));

   /* Append to record data */
   ret &= fpi_byte_writer_put_data(writer, encrypted, encrypted_size);

error:
   return ret;
}

static gboolean generate_and_store_aead_keys(FpiDeviceSynaTudorMoc *self,
                                             GError **error)
{
   gboolean ret = TRUE;
   g_autofree guint8 *data = NULL;

   gsize key_size = self->tls.encryption_key.size;
   if (!tls_prf(self->tls.master_secret, self->tls.mac_algo, "key expansion",
                self->tls.derive_input, sizeof(self->tls.derive_input), &data,
                4 * key_size, error)) {
      ret = FALSE;
      goto error;
   }

#ifdef TLS_DEBUG
   fp_dbg("key expansion data:");
   fp_dbg_large_hex(data, 4 * key_size);
#endif

   g_assert(self->tls.encryption_key.size != 0);
   g_assert(self->tls.decryption_key.size != 0);
   g_assert(self->tls.encryption_iv.size != 0);
   g_assert(self->tls.decryption_iv.size != 0);

   /* store parameters */
   guint offset = 0;
   self->tls.encryption_key.data =
       g_memdup2(data, self->tls.encryption_key.size);
   offset += self->tls.encryption_key.size;

   self->tls.decryption_key.data =
       g_memdup2(data + offset, self->tls.decryption_key.size);
   offset += self->tls.decryption_key.size;

   self->tls.encryption_iv.data =
       g_memdup2(data + offset, self->tls.encryption_iv.size);
   offset += self->tls.encryption_iv.size;

   self->tls.decryption_iv.data =
       g_memdup2(data + offset, self->tls.decryption_iv.size);
   offset += self->tls.decryption_iv.size;
   g_assert(offset <= 4 * key_size);

error:
   return ret;
}

static gboolean tls_aead_encryption_algorithm_init(FpiDeviceSynaTudorMoc *self,
                                                   GError **error)
{
   gboolean ret = TRUE;

   self->tls.encrypt_seq_num = 0;
   self->tls.decrypt_seq_num = 0;

   self->tls.encryption_key.size = AES_GCM_KEY_SIZE;
   self->tls.decryption_key.size = AES_GCM_KEY_SIZE;

   self->tls.decryption_iv.size = AES_GCM_IV_SIZE;
   self->tls.encryption_iv.size = AES_GCM_IV_SIZE;

   self->tls.tag_size = AES_GCM_TAG_SIZE;
   self->tls.cipher_alg = GNUTLS_CIPHER_AES_256_GCM;

   ret = generate_and_store_aead_keys(self, error);

   return ret;
}

static gboolean serialize_record(const record_t *to_serialize,
                                 guint8 **serialized, gsize *serialized_len)
{
   gboolean ret = TRUE;

   *serialized_len = RECORD_HEADER_SIZE + to_serialize->msg_len;
   *serialized = g_malloc(*serialized_len);

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, *serialized, *serialized_len, FALSE);
   ret &= fpi_byte_writer_put_uint8(&writer, to_serialize->type);
   ret &= fpi_byte_writer_put_uint8(&writer, to_serialize->version_major);
   ret &= fpi_byte_writer_put_uint8(&writer, to_serialize->version_minor);
   ret &= fpi_byte_writer_put_uint16_be(&writer, to_serialize->msg_len);
   ret &= fpi_byte_writer_put_data(&writer, to_serialize->msg,
                                   to_serialize->msg_len);

   if ((!ret) && (*serialized != NULL)) {
      g_free(*serialized);
   }

   return ret;
}

gboolean tls_wrap(FpiDeviceSynaTudorMoc *self, guint8 *ptext, gsize ptext_size,
                  guint8 **ctext, gsize *ctext_size, GError **error)
{
   gboolean ret = TRUE;
   gboolean written = TRUE;
   g_autofree guint8 *encrypted_msg = NULL;

   if (!self->tls.established) {
      fp_warn("Calling wrap while TLS session is not established");
      *ctext = ptext;
      *ctext_size = ptext_size;
      return ret;
   }

   record_t record_to_encrypt = {
       .type = RECORD_TYPE_APPLICATION_DATA,
       .version_major = self->tls.version_major,
       .version_minor = self->tls.version_minor,
       .msg = ptext,
       .msg_len = ptext_size,
   };

   g_autofree guint8 *encrypted_record = NULL;
   gsize encrypted_record_size = 0;
   BOOL_CHECK(encrypt_record(self, &record_to_encrypt, &encrypted_record,
                             &encrypted_record_size, error));

   *ctext_size = RECORD_HEADER_SIZE + encrypted_record_size;
   *ctext = g_malloc(*ctext_size);

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, *ctext, *ctext_size, FALSE);
   written &= write_record_header(&writer, &record_to_encrypt);
   written &= fpi_byte_writer_put_uint16_be(&writer, encrypted_record_size);
   written &= fpi_byte_writer_put_data(&writer, encrypted_record,
                                       encrypted_record_size);

   WRITTEN_CHECK(written);

error:
   if (!ret && *ctext != NULL) {
      g_free(*ctext);
      *ctext = NULL;
   }
   return ret;
}

gboolean tls_unwrap(FpiDeviceSynaTudorMoc *self, guint8 *ctext,
                    gsize ctext_size, guint8 **ptext, gsize *ptext_size,
                    GError **error)
{
   gboolean ret = TRUE;

   if (!self->tls.established) {
      fp_warn("Calling unwrap while tls is not established");
      *ptext = ctext;
      *ptext_size = ctext_size;
      return ret;
   }

   record_t encrypted_record = {0};
   BOOL_CHECK(read_record(ctext, ctext_size, &encrypted_record));

   BOOL_CHECK(
       decrypt_record(self, &encrypted_record, ptext, ptext_size, error));

   if (encrypted_record.type == RECORD_TYPE_ALERT) {
      log_tls_alert_msg((*ptext)[0], (*ptext)[1]);
      self->tls.established = FALSE;
      self->tls.remote_sends_encrypted = FALSE;
      ret = FALSE;
   }

error:
   if (!ret && *ptext != NULL) {
      g_free(*ptext);
      *ptext = NULL;
   }
   if (encrypted_record.msg != NULL) {
      g_free(encrypted_record.msg);
   }
   return ret;
}

static gboolean send_tls_alert(FpiDeviceSynaTudorMoc *self,
                               gnutls_alert_level_t alert_level,
                               gnutls_alert_description_t alert_desc,
                               GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *send_data = NULL;
   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *encrypted = NULL;

   record_t record_to_encrypt = {
       .type = RECORD_TYPE_ALERT,
       .version_major = self->tls.version_major,
       .version_minor = self->tls.version_minor,
       .msg_len = 2,
   };

   guint8 msg[record_to_encrypt.msg_len];
   msg[0] = alert_level;
   msg[1] = alert_desc;
   record_to_encrypt.msg = msg;

   gsize encrypted_size = 0;
   BOOL_CHECK(encrypt_record(self, &record_to_encrypt, &encrypted,
                             &encrypted_size, error));

   const gsize send_size = RECORD_HEADER_SIZE + encrypted_size;
   send_data = g_malloc(send_size);

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);

   gboolean written = TRUE;
   written &= write_record_header(&writer, &record_to_encrypt);
   written &= fpi_byte_writer_put_uint16_be_inline(&writer, encrypted_size);
   written &= fpi_byte_writer_put_data(&writer, encrypted, encrypted_size);
   WRITTEN_CHECK(written);

   gsize recv_data_size = 256;
   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_data_size, FALSE, error));

   BOOL_CHECK(
       parse_and_process_records(self, recv_data, recv_data_size, error));

error:
   return ret;
}

gboolean tls_close_session(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   /* turn if off now, as we do not want the encrypted command to be wrapped */
   self->tls.established = FALSE;

   BOOL_CHECK(
       send_tls_alert(self, GNUTLS_AL_WARNING, GNUTLS_A_CLOSE_NOTIFY, error));

error:
   return ret;
}

/* Establish session funcitons ============================================= */

static gboolean tls_handshake_state_prepare(FpiDeviceSynaTudorMoc *self)
{
   gboolean ret = TRUE;

   self->tls.version_major = TLS_PROTOCOL_VERSION_MAJOR;
   self->tls.version_minor = TLS_PROTOCOL_VERSION_MINOR;
   self->tls.remote_sends_encrypted = FALSE;
   self->tls.sent_handshake_msgs = NULL;
   self->tls.sent_handshake_msgs_size = 0;
   self->tls.sent_handshake_msgs_alloc_size = 0;

   self->tls.handshake_state += 1; /* TLS_HS_STATE_START */

   return ret;
}

gboolean load_sample_pairing_data(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   /* load sample certificates for now */
   BOOL_CHECK(parse_certificate(sample_sensor_cert, CERTIFICATE_SIZE,
                                &self->pairing_data.sensor_cert));

   BOOL_CHECK(parse_certificate(sample_recv_host_cert, CERTIFICATE_SIZE,
                                &self->pairing_data.host_cert));

   g_assert(!self->pairing_data.private_key_initialized);
   GNUTLS_CHECK(gnutls_privkey_init(&self->pairing_data.private_key));
   self->pairing_data.private_key_initialized = TRUE;

   /* load sample private key for now */
   GNUTLS_CHECK(gnutls_privkey_import_ecc_raw(
       self->pairing_data.private_key, GNUTLS_ECC_CURVE_SECP256R1,
       &sample_privkey_x_datum, &sample_privkey_y_datum,
       &sample_privkey_k_datum));
   self->pairing_data.private_key_initialized = TRUE;

   GNUTLS_CHECK(gnutls_privkey_verify_params(self->pairing_data.private_key));

   self->pairing_data.present = TRUE;

error:
   return ret;
}

static gboolean tls_handshake_state_start(FpiDeviceSynaTudorMoc *self,
                                          GError **error)
{
   gboolean ret = TRUE;
   g_autofree guint8 *recv_data = NULL;

   hello_t client_hello = {.extensions = NULL};
   BOOL_CHECK(init_client_hello(self, &client_hello));

   record_t client_hello_record = {.msg = NULL};
   BOOL_CHECK(
       get_client_hello_record(self, &client_hello, &client_hello_record));

   /* update stored all sent msg data */
   update_handshake_messages_data_record(self, &client_hello_record);

   gsize recv_data_size;

   BOOL_CHECK(send_tls(self, &client_hello_record, 1, &recv_data,
                       &recv_data_size, TRUE, error));

   if (!parse_and_process_records(self, recv_data, recv_data_size, error)) {
      goto error;
   }

   self->tls.handshake_state = TLS_HS_STATE_END;

error:
   if (client_hello_record.msg != NULL) {
      g_free(client_hello_record.msg);
   }
   if (client_hello.extensions != NULL) {
      g_free(client_hello.extensions);
   }
   return ret;
}

static gboolean calculate_premaster_secret(FpiDeviceSynaTudorMoc *self,
                                           gnutls_privkey_t privkey,
                                           gnutls_datum_t *premaster_secret,
                                           GError **error)
{
   gboolean ret = TRUE;
   gboolean pubkey_initialized = FALSE;

   g_autofree guint8 *pubkey_x_data = g_malloc(ECC_KEY_SIZE);
   g_autofree guint8 *pubkey_y_data = g_malloc(ECC_KEY_SIZE);

   /* get sensor pubkey */
   gnutls_pubkey_t sensor_pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&sensor_pubkey));

   pubkey_initialized = TRUE;

   g_assert(self->pairing_data.sensor_cert.curve == 23);

   /* NOTE: the keys are stored in little endian - reverse them as gnutls seems
    to expect big endian */
   gnutls_datum_t pubkey_x = {.size = ECC_KEY_SIZE, .data = pubkey_x_data};
   gnutls_datum_t pubkey_y = {.size = ECC_KEY_SIZE, .data = pubkey_y_data};
   memcpy(pubkey_x.data, self->pairing_data.sensor_cert.pubkey_x, ECC_KEY_SIZE);
   memcpy(pubkey_y.data, self->pairing_data.sensor_cert.pubkey_y, ECC_KEY_SIZE);
   reverse_array(pubkey_x.data, pubkey_x.size);
   reverse_array(pubkey_y.data, pubkey_y.size);

   GNUTLS_CHECK(gnutls_pubkey_import_ecc_raw(
       sensor_pubkey, GNUTLS_ECC_CURVE_SECP256R1, &pubkey_x, &pubkey_y));

   GNUTLS_CHECK(gnutls_pubkey_verify_params(sensor_pubkey));

   /* derive premaster_secret */
   GNUTLS_CHECK(gnutls_privkey_derive_secret(privkey, sensor_pubkey, NULL,
                                             premaster_secret, 0));

error:
   if (pubkey_initialized) {
      gnutls_pubkey_deinit(sensor_pubkey);
   }
   return ret;
}

static gboolean calculate_master_secret(FpiDeviceSynaTudorMoc *self,
                                        gnutls_privkey_t privkey,
                                        GError **error)
{
   gboolean ret = TRUE;

   gnutls_datum_t premaster_secret = {.data = NULL, .size = 0};
   BOOL_CHECK(
       calculate_premaster_secret(self, privkey, &premaster_secret, error));

#ifdef TLS_DEBUG
   fp_dbg("premaster_secret:");
   fp_dbg_large_hex(premaster_secret.data, premaster_secret.size);
#endif

   /* prepare derive_input */
   memcpy(self->tls.derive_input, self->tls.client_random,
          sizeof(self->tls.client_random));
   memcpy(self->tls.derive_input + sizeof(self->tls.client_random),
          self->tls.server_random, sizeof(self->tls.server_random));

   /* calculate master secret */
   self->tls.master_secret.size = MASTER_SECRET_SIZE;

#ifdef TLS_DEBUG
   fp_dbg("calculating master secret form:");
   fp_dbg("\tpremaster secret:");
   fp_dbg_large_hex(premaster_secret.data, premaster_secret.size);
   fp_dbg("\tseed:");
   fp_dbg_large_hex(self->tls.derive_input, sizeof(self->tls.derive_input));
#endif

   ret &= tls_prf(premaster_secret, self->tls.mac_algo, "master secret",
                  self->tls.derive_input, sizeof(self->tls.derive_input),
                  &self->tls.master_secret.data, self->tls.master_secret.size,
                  error);
#ifdef TLS_DEBUG
   fp_dbg("master_secret:");
   fp_dbg_large_hex(self->tls.master_secret.data, self->tls.master_secret.size);
#endif

error:
   if (premaster_secret.data != NULL) {
      g_free(premaster_secret.data);
   }
   return ret;
}

static gboolean tls_handshake_state_end(FpiDeviceSynaTudorMoc *self,
                                        GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *recv_data = NULL;
   gboolean privkey_initialized = FALSE;

   record_t records_to_send[3];
   records_to_send[0].msg = NULL;
   records_to_send[1].msg = NULL;
   records_to_send[2].msg = NULL;

   records_to_send[0].type = RECORD_TYPE_HANDSHAKE;
   records_to_send[0].version_major = self->tls.version_major;
   records_to_send[0].version_minor = self->tls.version_minor;

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init(&writer);

   /* others not implemented */
   g_assert(self->tls.requested_cert == TLS_CERT_TYPE_ECDSA_SIGN);

   gsize client_cert_pos_before = fpi_byte_writer_get_pos(&writer);
   written &= append_client_certificate(self, &writer);
   gsize client_cert_pos_after = fpi_byte_writer_get_pos(&writer);

   /* update stored all sent msg data */
   update_handshake_messages_data(
       self, writer.parent.data + client_cert_pos_before,
       client_cert_pos_after - client_cert_pos_before);

   gnutls_privkey_t privkey;
   GNUTLS_CHECK(gnutls_privkey_init(&privkey));
   privkey_initialized = TRUE;
   GNUTLS_CHECK(gnutls_privkey_generate(
       privkey, GNUTLS_PK_ECDSA,
       GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0));

#ifdef TLS_DEBUG
   gnutls_datum_t x;
   gnutls_datum_t y;
   gnutls_datum_t k;
   gnutls_ecc_curve_t curve;
   gnutls_privkey_export_ecc_raw(privkey, &curve, &x, &y, &k);
   fp_dbg("Eph ecc key data:");
   fp_dbg("\tx");
   fp_dbg_large_hex(x.data, x.size);
   fp_dbg("\ty");
   fp_dbg_large_hex(y.data, y.size);
   fp_dbg("\tk");
   fp_dbg_large_hex(k.data, k.size);
#endif

   gsize client_kex_pos_before = fpi_byte_writer_get_pos(&writer);
   written &= append_client_key_exchange_to_record(&writer, &privkey, error);
   gsize client_kex_pos_after = fpi_byte_writer_get_pos(&writer);

   /* update stored all sent msg data */
   update_handshake_messages_data(self,
                                  writer.parent.data + client_kex_pos_before,
                                  client_kex_pos_after - client_kex_pos_before);

   gsize cert_verify_pos_before = fpi_byte_writer_get_pos(&writer);
   written &= append_certificate_verify_to_record(self, &writer, error);
   gsize cert_verify_pos_after = fpi_byte_writer_get_pos(&writer);

   records_to_send[0].msg_len = fpi_byte_writer_get_pos(&writer);
   records_to_send[0].msg = fpi_byte_writer_reset_and_get_data(&writer);

   /* update stored all sent msg data */
   update_handshake_messages_data(
       self, records_to_send[0].msg + cert_verify_pos_before,
       cert_verify_pos_after - cert_verify_pos_before);

   if (!written) {
      fp_err("%s: error while writing first part", __FUNCTION__);
   }

   /* send change cipher spec */
   records_to_send[1].type = RECORD_TYPE_CHANGE_CIPHER_SPEC;
   records_to_send[1].version_major = self->tls.version_major;
   records_to_send[1].version_minor = self->tls.version_minor;

   fpi_byte_writer_init(&writer);
   written &= fpi_byte_writer_put_uint8(&writer, 0x01);
   records_to_send[1].msg_len = fpi_byte_writer_get_pos(&writer);
   records_to_send[1].msg = fpi_byte_writer_reset_and_get_data(&writer);

   if (!written) {
      fp_err("%s: error while writing second part", __FUNCTION__);
   }

   /* derive master secret and init en/decryption algorithm */
   BOOL_CHECK(calculate_master_secret(self, privkey, error));
   BOOL_CHECK(tls_aead_encryption_algorithm_init(self, error));

   /* send handshake finished */
   records_to_send[2].type = RECORD_TYPE_HANDSHAKE;
   records_to_send[2].version_major = self->tls.version_major;
   records_to_send[2].version_minor = self->tls.version_minor;

   fpi_byte_writer_init(&writer);
   written &= append_encrypted_handshake_finish_to_record(self, &writer, error);
   records_to_send[2].msg_len = fpi_byte_writer_get_pos(&writer);
   records_to_send[2].msg = fpi_byte_writer_reset_and_get_data(&writer);

   if (!written) {
      fp_err("%s: error while writing third part", __FUNCTION__);
   }

   WRITTEN_CHECK(written);

   gsize recv_size;
   BOOL_CHECK(
       send_tls(self, records_to_send, 3, &recv_data, &recv_size, TRUE, error));

   BOOL_CHECK(parse_and_process_records(self, recv_data, recv_size, error));

   self->tls.handshake_state = TLS_HS_STATE_FINISHED;

error:
   if (privkey_initialized) {
      gnutls_privkey_deinit(privkey);
   }
   if (records_to_send[0].msg != NULL) {
      g_free(records_to_send[0].msg);
   }
   if (records_to_send[1].msg != NULL) {
      g_free(records_to_send[1].msg);
   }
   if (records_to_send[2].msg != NULL) {
      g_free(records_to_send[2].msg);
   }

   return ret;
}

gboolean establish_tls_session(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;
   fp_dbg("Establishing TLS session");

   gboolean remote_established = FALSE;
   BOOL_CHECK(get_remote_tls_status(self, &remote_established, error));

   /* a check should be done beforehand */
   g_assert(!self->tls.established && !remote_established);

   self->tls.handshake_state = TLS_HS_STATE_PREPARE;

   while (!self->tls.established) {
      if (g_cancellable_is_cancelled(self->cancellable)) {
         fp_warn("Establishing of TLS was cancelled");
         ret = FALSE;
         goto error;
      }
      fp_dbg("TLS handshake state: %d", self->tls.handshake_state);

      switch (self->tls.handshake_state) {
      case TLS_HS_STATE_PREPARE:
         fp_dbg("TLS handshake state: prepare");
         if (!tls_handshake_state_prepare(self)) {
            self->tls.handshake_state = TLS_HS_STATE_FAILED;
            ret = FALSE;
            goto error;
         }
         break;
      case TLS_HS_STATE_START:
         fp_dbg("TLS handshake state: sending client hello");
         if (!tls_handshake_state_start(self, error)) {
            self->tls.handshake_state = TLS_HS_STATE_FAILED;
         }
         break;
      case TLS_HS_STATE_END:
         fp_dbg("TLS handshake state: sending certificate and key");
         if (!tls_handshake_state_end(self, error)) {
            self->tls.handshake_state = TLS_HS_STATE_FAILED;
         }
         self->tls.sent_handshake_msgs_alloc_size = 0;
         self->tls.sent_handshake_msgs_size = 0;
         if (self->tls.sent_handshake_msgs != NULL) {
            g_free(self->tls.sent_handshake_msgs);
         }
         break;

      case TLS_HS_STATE_ALERT:
         fp_err("TLS Alert generated during handshake");
         fp_dbg("\t TLS alert: level = %d; description = %d = %s",
                self->tls.alert_level, self->tls.alert_desc,
                gnutls_alert_get_strname(self->tls.alert_desc));
         if (!send_tls_alert(self, self->tls.alert_level, self->tls.alert_desc,
                             error)) {
            fp_warn("Unable to send TLS alert");
         }
         self->tls.handshake_state += 1; /* TLS_HS_STATE_FAILED */
         break;

      case TLS_HS_STATE_FAILED:
         self->tls.sent_handshake_msgs_alloc_size = 0;
         self->tls.sent_handshake_msgs_size = 0;
         if (self->tls.sent_handshake_msgs != NULL) {
            g_free(self->tls.sent_handshake_msgs);
         }
         self->tls.established = FALSE;
         /* reset state for later calling of this function */
         self->tls.handshake_state = TLS_HS_STATE_PREPARE;

         /* propagate error if present */
         if (*error != NULL) {
            *error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                          "TLS handshake failed");
         }

         ret = FALSE;
         goto error;
         break;

      case TLS_HS_STATE_FINISHED:
         fp_dbg("TLS handshake done");
         self->tls.established = TRUE;
         break;

      default:
         fp_err("Unimplemented handshake state: %d", self->tls.handshake_state);
         BUG();
      }
   }
error:
   if (!ret) {
      fp_err("Error in function %s", __FUNCTION__);
   }
   return ret;
}

/* ========================================================================= */
static gboolean
sensor_pub_key_compatibility_check(FpiDeviceSynaTudorMoc *self,
                                   sensor_pub_key_t *sensor_pubkey,
                                   GError **error)
{
   gboolean ret = TRUE;

   gboolean key_flag = (self->mis_version.security & 0x20) != 0;
   if (sensor_pubkey->keyflag != key_flag) {
      ret = FALSE;
      *error = set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                                    "Sensor pubkey keyflag does not match");
   } else if (sensor_pubkey->fw_version_major !=
              self->mis_version.version_major) {
      ret = FALSE;
      *error = set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                                    "Sensor pubkey fw_version_major does "
                                    "not match - expected: %d, got: %d",
                                    sensor_pubkey->fw_version_major,
                                    self->mis_version.version_major);
   } else if (sensor_pubkey->fw_version_minor !=
              self->mis_version.version_minor) {
      ret = FALSE;
      *error = set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                                    "Sensor pubkey fw_version_minor does "
                                    "not match - expected: %d, got: %d",
                                    sensor_pubkey->fw_version_minor,
                                    self->mis_version.version_minor);
   }
   return ret;
}

gboolean verify_sensor_certificate(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;
   gboolean pubkey_initialized = FALSE;

   gboolean key_flag = (self->mis_version.security & 0x20) != 0;

   /* get sensor public key */
   gnutls_pubkey_t pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&pubkey));
   pubkey_initialized = TRUE;

   fp_dbg("Sensor certificate verify key_flag: %d", key_flag);
   sensor_pub_key_t sensor_pub_key;
   if (key_flag) {
      sensor_pub_key = pubkey_v10_1_kf;
   } else {
      sensor_pub_key = pubkey_v10_1;
   }

   BOOL_CHECK(sensor_pub_key_compatibility_check(self, &sensor_pub_key, error));
   GNUTLS_CHECK(gnutls_pubkey_import_ecc_raw(pubkey, GNUTLS_ECC_CURVE_SECP256R1,
                                             &sensor_pub_key.x,
                                             &sensor_pub_key.y));
   GNUTLS_CHECK(gnutls_pubkey_verify_params(pubkey));

   /* everything up to signature */
   gnutls_datum_t data = {.size = CERTIFICATE_SIZE_WITHOUT_SIGNATURE,
                          .data = (guint8 *)&self->pairing_data.sensor_cert};
   gnutls_datum_t signature = {.size = self->pairing_data.sensor_cert.sign_size,
                               .data =
                                   self->pairing_data.sensor_cert.sign_data};

   GNUTLS_CHECK(gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0,
                                           &data, &signature));

   fp_dbg("Sensor certificate verify success");

error:
   if (pubkey_initialized) {
      gnutls_pubkey_deinit(pubkey);
   }
   return ret;
}

/* ========================================================================= */

void deinit_tls(FpiDeviceSynaTudorMoc *self)
{
   if (self->tls.master_secret.data != NULL) {
      g_free(self->tls.master_secret.data);
   }
   if (self->tls.encryption_key.data != NULL) {
      g_free(self->tls.encryption_key.data);
   }
   if (self->tls.decryption_key.data != NULL) {
      g_free(self->tls.decryption_key.data);
   }
   if (self->tls.encryption_iv.data != NULL) {
      g_free(self->tls.encryption_iv.data);
   }
   if (self->tls.decryption_iv.data != NULL) {
      g_free(self->tls.decryption_iv.data);
   }
}

void free_pairing_data(FpiDeviceSynaTudorMoc *self)
{
   if (self->pairing_data.private_key_initialized) {
      gnutls_privkey_deinit(self->pairing_data.private_key);
      self->pairing_data.private_key_initialized = FALSE;
   }
   self->pairing_data.present = FALSE;
}

gboolean handle_tls_statuses_for_sensor_and_host(FpiDeviceSynaTudorMoc *self,
                                                 GError **error)
{
   gboolean ret = TRUE;

   /* Get and handle TLS statuses for sensor and host */
   gboolean remote_tls_status = FALSE;
   BOOL_CHECK(get_remote_tls_status(self, &remote_tls_status, error));

   if (self->tls.established && !remote_tls_status) {
      fp_warn("Host is in TLS session but sensor is not");
      self->tls.established = FALSE;

   } else if (!self->tls.established && remote_tls_status) {
      fp_warn("Sensor is in TLS session but host is not");
      BOOL_CHECK(send_cmd_to_force_close_sensor_tls_session(self, error));

      /* check for success */
      remote_tls_status = FALSE;
      BOOL_CHECK(get_remote_tls_status(self, &remote_tls_status, error));
      if (remote_tls_status) {
         *error = set_and_report_error(
             FP_DEVICE_ERROR_PROTO,
             "Unable to get the sensor out of TLS session");
         goto error;
      }

   } else if (self->tls.established && remote_tls_status) {
      fp_dbg("Host and sensor are already in TLS session");
   }

error:
   return ret;
}

static gboolean sensor_supports_advanced_security(FpiDeviceSynaTudorMoc *self)
{
   return (self->mis_version.security & 0x100) != 0;
}

/* Pairing functions ======================================================= */

static gboolean generate_hs_priv_key(gnutls_privkey_t *privkey, GError **error)
{
   gboolean ret = TRUE;
   gboolean privkey_initialized = FALSE;
   g_return_val_if_fail(privkey != NULL, FALSE);

   /* TODO: figure out how to import an ecc key with only k parameter */
   /* guint8 secret[] = {0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
                      0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19};
   gnutls_datum_t secret_datum = {.data = secret, .size = sizeof(secret)};
   const guint8 seed[] = {0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38,
                          0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33, 0xaa, 0xaa};
   const char *label = "HS_KEY_PAIR_GEN";

   g_autofree guint8 *output = NULL;
   const gsize output_len = 32;
   BOOL_CHECK(tls_prf(secret_datum, GNUTLS_MAC_SHA256, label, seed,
                      sizeof(seed), &output, output_len, error)); */

   /* gnutls expects big-endian, while output is in little */
   /* reverse_array(output, output_len);
   gnutls_datum_t k = {.data = output, .size = output_len};

   GNUTLS_CHECK(gnutls_privkey_init(privkey));
   privkey_initialized = TRUE;

   GNUTLS_CHECK(gnutls_privkey_import_ecc_raw(
       *privkey, GNUTLS_ECC_CURVE_SECP256R1, NULL, NULL, &k)); */

   /* HS_KEY_PAIR_GEN result, then converted to big-endian as expected by gnutls
    */
   guint8 k[ECC_KEY_SIZE] = {0xe8, 0xa2, 0xa2, 0xb6, 0x65, 0x62, 0x54, 0xd6,
                             0xac, 0xb0, 0xef, 0x47, 0x9c, 0xae, 0x41, 0x40,
                             0xc7, 0xe8, 0xe2, 0x60, 0xdb, 0x3f, 0x64, 0x2e,
                             0x35, 0xd4, 0x09, 0x9c, 0x01, 0xb3, 0x6a, 0x86};
   gnutls_datum_t k_datum = {.data = k, .size = ECC_KEY_SIZE};
   guint8 x[ECC_KEY_SIZE] = {0x89, 0xe5, 0x41, 0x30, 0x0c, 0xcf, 0x1a, 0x03,
                             0xe6, 0x25, 0xc4, 0x3d, 0xf7, 0x25, 0xc5, 0x95,
                             0x78, 0x7a, 0x71, 0xcb, 0x03, 0x5b, 0x4b, 0x7c,
                             0x06, 0xd3, 0x51, 0x71, 0x42, 0x2e, 0x50, 0x57};
   gnutls_datum_t x_datum = {.data = x, .size = ECC_KEY_SIZE};
   guint8 y[ECC_KEY_SIZE] = {0xeb, 0x05, 0x00, 0x8f, 0x22, 0xaa, 0x2b, 0xc6,
                             0xfe, 0x0b, 0xf9, 0x08, 0x03, 0xa0, 0xe7, 0x3a,
                             0x2e, 0xb2, 0x8c, 0xfd, 0x0c, 0x72, 0xa5, 0xf6,
                             0x73, 0x35, 0xc0, 0x61, 0x22, 0x6e, 0xff, 0xec};
   gnutls_datum_t y_datum = {.data = y, .size = ECC_KEY_SIZE};

   GNUTLS_CHECK(gnutls_privkey_init(privkey));
   privkey_initialized = TRUE;

   GNUTLS_CHECK(gnutls_privkey_import_ecc_raw(
       *privkey, GNUTLS_ECC_CURVE_SECP256R1, &x_datum, &y_datum, &k_datum));

error:
   if (!ret && privkey_initialized) {
      gnutls_privkey_deinit(*privkey);
   }
   return ret;
}

static gboolean create_host_certificate(FpiDeviceSynaTudorMoc *self,
                                        guint8 *host_certificate,
                                        GError **error)
{
   gboolean ret = TRUE;

   gboolean pubkey_initialized = FALSE;
   gboolean hs_privkey_initialized = FALSE;
   gnutls_datum_t signature = {.data = NULL};
   gnutls_datum_t x = {.data = NULL};
   gnutls_datum_t y = {.data = NULL};

   /* get public key */
   gnutls_pubkey_t pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&pubkey));
   pubkey_initialized = TRUE;
   GNUTLS_CHECK(gnutls_pubkey_import_privkey(pubkey,
                                             self->pairing_data.private_key,
                                             GNUTLS_KEY_DIGITAL_SIGNATURE, 0));

   GNUTLS_CHECK(gnutls_pubkey_export_ecc_raw(pubkey, NULL, &x, &y));

   /* as the size of public key x and y is up to 68 we need to zero the unused
    * bytes */
   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, host_certificate, CERTIFICATE_SIZE,
                                  FALSE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint16_le(&writer, CERTIFICATE_MAGIC);
   written &= fpi_byte_writer_put_uint16_le(&writer, CERTIFICATE_CURVE);

   reverse_array(x.data, x.size);
   written &= fpi_byte_writer_put_data(&writer, x.data, x.size);
   /* add zeros as padding */
   written &= fpi_byte_writer_fill(&writer, 0, 68 - x.size);
   reverse_array(y.data, y.size);
   written &= fpi_byte_writer_put_data(&writer, y.data, y.size);
   /* add zeros as padding */
   written &= fpi_byte_writer_fill(&writer, 0, 68 - y.size);
   /* add padding */
   written &= fpi_byte_writer_put_uint8(&writer, 0);
   /* put certificate type */
   written &= fpi_byte_writer_put_uint8(&writer, 0);
   WRITTEN_CHECK(written);

   g_assert(fpi_byte_writer_get_pos(&writer) ==
            CERTIFICATE_SIZE_WITHOUT_SIGNATURE);

   gnutls_privkey_t hs_privkey;
   BOOL_CHECK(generate_hs_priv_key(&hs_privkey, error));
   hs_privkey_initialized = TRUE;

   gnutls_datum_t to_sign = {.data = host_certificate,
                             .size = CERTIFICATE_SIZE_WITHOUT_SIGNATURE};
   GNUTLS_CHECK(gnutls_privkey_sign_data(hs_privkey, GNUTLS_DIG_SHA256, 0,
                                         &to_sign, &signature));
   g_assert(signature.size <= SIGNATURE_SIZE);

   written &= fpi_byte_writer_put_uint16_le(&writer, signature.size);

   written &= fpi_byte_writer_put_data(&writer, signature.data, signature.size);
   /* add zeros as padding */
   written &= fpi_byte_writer_fill(&writer, 0, SIGNATURE_SIZE - signature.size);
   WRITTEN_CHECK(written);
   g_assert(fpi_byte_writer_get_pos(&writer) == CERTIFICATE_SIZE);

error:
   if (pubkey_initialized) {
      gnutls_pubkey_deinit(pubkey);
   }
   if (hs_privkey_initialized) {
      gnutls_privkey_deinit(hs_privkey);
   }
   if (signature.data != NULL) {
      g_free(signature.data);
   }
   if (x.data != NULL) {
      g_free(x.data);
   }
   if (y.data != NULL) {
      g_free(y.data);
   }
   return ret;
}

gboolean pair(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *host_certificate = g_malloc(CERTIFICATE_SIZE);

   if (self->mis_version.provision_state != PROVISION_STATE_PROVISIONED) {
      fp_warn("Skipping pairing: sensor is already paired or insecure");
      goto error;
   }

   if (!sensor_supports_advanced_security(self)) {
      fp_warn("Skipping pairing: only advanced security is supporeted");
      goto error;
   }

   fp_dbg("Pairing sensor");

   /* Create keypair */
   GNUTLS_CHECK(gnutls_privkey_init(&self->pairing_data.private_key));
   self->pairing_data.private_key_initialized = TRUE;
   GNUTLS_CHECK(gnutls_privkey_generate(
       self->pairing_data.private_key, GNUTLS_PK_ECDSA,
       GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0));

   /* we create it already serialized, as we do not need it in struct form */
   BOOL_CHECK(create_host_certificate(self, host_certificate, error));

   /* saves received certificates to self */
   BOOL_CHECK(send_pair(self, host_certificate, error));

error:
   return ret;
}
