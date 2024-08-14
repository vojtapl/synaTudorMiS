/*
 * TODO: header
 */

#include "communication.h"
#include "device.h"
#include "drivers_api.h"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-usb-transfer.h"
#include "sample_pairing_data.h"
#include "tls.h"
#include "utils.h"
#include <gio/gio.h>
#include <glib.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

// #define TLS_DEBUG

#define GNUTLS_CHECK(func_call)                                                \
   do {                                                                        \
      gint gnutls_ret = (func_call);                                           \
      if (gnutls_ret != GNUTLS_E_SUCCESS) {                                    \
         fp_err("GnuTLS error in " #func_call ": %s",                          \
                gnutls_strerror(gnutls_ret));                                  \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)

static cipher_suit_t tls_ecdh_ecdsa_with_aes_256_gcm_sha384 = {
    .id = 0xC02E,
};
// set supported curve to 0x17=23
static guint8 supported_groups_data[4] = {0x00, 0x02, 0x00, 0x17};
static extension_t supported_groups = {
    .id = 0xa, .len = 4, .data = supported_groups_data};
// set ec_point_formats to 0
static guint8 ec_point_formats_data[2] = {0x01, 0x00};
static extension_t ec_point_formats = {
    .id = 0xb, .len = 2, .data = ec_point_formats_data};

/*===========================================================================*/

static void
event_mask_to_event_buffer(guint32 event_mask,
                           sensor_event_type_t event_buffer[NUM_EVENTS])
{
   guint event_num = 0;
   if ((event_mask & NO_EVENTS) != 0) {
      event_buffer[event_num++] = NO_EVENTS;
   } else if ((event_mask & NO_EVENTS) != 0) {
      event_buffer[event_num++] = NO_EVENTS;
   } else if ((event_mask & EV_FINGER_DOWN) != 0) {
      event_buffer[event_num++] = EV_FINGER_DOWN;
   } else if ((event_mask & EV_FINGER_UP) != 0) {
      event_buffer[event_num++] = EV_FINGER_UP;
   } else if ((event_mask & EV_3) != 0) {
      event_buffer[event_num++] = EV_3;
   } else if ((event_mask & EV_4) != 0) {
      event_buffer[event_num++] = EV_4;
   } else if ((event_mask & EV_5) != 0) {
      event_buffer[event_num++] = EV_5;
   } else if ((event_mask & EV_6) != 0) {
      event_buffer[event_num++] = EV_6;
   } else if ((event_mask & EV_7) != 0) {
      event_buffer[event_num++] = EV_7;
   } else if ((event_mask & EV_8) != 0) {
      event_buffer[event_num++] = EV_8;
   } else if ((event_mask & EV_9) != 0) {
      event_buffer[event_num++] = EV_9;
   } else if ((event_mask & EV_FRAME_READY) != 0) {
      event_buffer[event_num++] = EV_FRAME_READY;
   }
}

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

static gboolean decrypt_record(FpiDeviceSynapticsMoc *self,
                               record_t *record_to_decrypt, guint8 **ptext,
                               gsize *ptext_len)
{
#ifdef TLS_DEBUG
   printf("Decrypting record msg:\n");
   print_array(record_to_decrypt->msg, record_to_decrypt->msg_len);
#endif

   gboolean ret = TRUE;
   gboolean crypt_initialized = FALSE;

   *ptext_len = 0;

   // Setup storage for additional data
   gsize additional_data_size =
       sizeof(self->tls.decrypt_seq_num) + RECORD_HEADER_SIZE;
   guint8 additional_data[additional_data_size];

   // Split input msg into nonce and crypttext
   guint64 nonce = FP_READ_UINT64_BE(record_to_decrypt->msg);
   guint8 *ctext = record_to_decrypt->msg + sizeof(nonce);
   gsize ctext_len = record_to_decrypt->msg_len - sizeof(nonce);
   gsize expected_ptext_len = ctext_len - self->tls.tag_size;

   // create GCM IV = decryption_iv + nonce
   gnutls_datum_t gcm_iv = {.data = NULL, .size = 0};
   g_assert(self->tls.decryption_iv.size != 0);
   gcm_iv.size = sizeof(nonce) + self->tls.decryption_iv.size;
   gcm_iv.data = g_malloc(gcm_iv.size * sizeof(*gcm_iv.data));
   memcpy(gcm_iv.data, self->tls.decryption_iv.data,
          self->tls.decryption_iv.size);
   FP_WRITE_UINT64_BE(gcm_iv.data + self->tls.decryption_iv.size, nonce);

#ifdef TLS_DEBUG
   fp_dbg("\ndecryption nonce: %lu", nonce);
   fp_dbg("\ndecryption IV:");
   print_array(self->tls.decryption_iv.data, self->tls.decryption_iv.size);
   fp_dbg("GCM IV:");
   print_array(gcm_iv.data, gcm_iv.size);
   fp_dbg("decryption key:");
   print_array(self->tls.decryption_key.data, self->tls.decryption_key.size);
#endif

   // Initialize GCM cipher
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
   g_assert(written); // NOTE: this should have no way of failing

   // Allocate for result
   gsize allocated_for_ptext = expected_ptext_len;
   *ptext = g_malloc(allocated_for_ptext);

#ifdef TLS_DEBUG
   fp_dbg("Decryption - auth data:");
   print_array(additional_data, additional_data_size);
#endif

   // Decrypt text
   GNUTLS_CHECK(gnutls_aead_cipher_decrypt(
       aead_hd, gcm_iv.data, gcm_iv.size, additional_data, additional_data_size,
       self->tls.tag_size, ctext, ctext_len, *ptext, &allocated_for_ptext));

   // Set decrypted text size (decryption may be shorter)
   *ptext_len = allocated_for_ptext;

   self->tls.decrypt_seq_num += 1;

#ifdef TLS_DEBUG
   printf("Decrypted:\n");
   print_array(*ptext, *ptext_len);
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

static const char *tls_alert_description_msg(const guint alert_description)
{
   const char *ret;
   switch (alert_description) {
   case 0:
      ret = "CLOSE_NOTIFY";
      break;
   case 10:
      ret = "UNEXPECTED_MESSAGE";
      break;
   case 20:
      ret = "BAD_RECORD_MAC";
      break;
   case 21:
      ret = "DECRYPTION_FAILED_RESERVED";
      break;
   case 22:
      ret = "RECORD_OVERFLOW";
      break;
   case 30:
      ret = "DECOMPRESSION_FAILURE";
      break;
   case 40:
      ret = "HANDSHAKE_FAILURE";
      break;
   case 41:
      ret = "NO_CERTIFICATE_RESERVED";
      break;
   case 42:
      ret = "BAD_CERTIFICATE";
      break;
   case 43:
      ret = "UNSUPPORTED_CERTIFICATE";
      break;
   case 44:
      ret = "CERTIFICATE_REVOKED";
      break;
   case 45:
      ret = "CERTIFICATE_EXPIRED";
      break;
   case 46:
      ret = "CERTIFICATE_UNKNOWN";
      break;
   case 47:
      ret = "ILLEGAL_PARAMETER";
      break;
   case 48:
      ret = "UNKNOWN_CA";
      break;
   case 49:
      ret = "ACCESS_DENIED";
      break;
   case 50:
      ret = "DECODE_ERROR";
      break;
   case 51:
      ret = "DECRYPT_ERROR";
      break;
   case 60:
      ret = "EXPORT_RESTRICTION_RESERVED";
      break;
   case 70:
      ret = "PROTOCOL_VERSION";
      break;
   case 71:
      ret = "INSUFFICIENT_SECURITY";
      break;
   case 80:
      ret = "INTERNAL_ERROR";
      break;
   case 90:
      ret = "USER_CANCELED";
      break;
   case 100:
      ret = "NO_RENEGOTIATION";
      break;
   case 110:
      ret = "UNSUPPORTED_EXTENSION";
      break;
   case 166:
      ret = "CLOSE_NOTIFY2";
      break;
   default:
      ret = "UNKNOWN";
      break;
   }
   return ret;
}

static void log_tls_alert_msg(const guint alert_level,
                              const guint alert_description)
{
   const char *alert_level_msg =
       alert_level == TLS_ALERT_LVL_WARNING ? "WARNING" : "FATAL";
   fp_err("Received TLS alert level %d aka %s with description: %u aka %s",
          alert_level, alert_level_msg, alert_description,
          tls_alert_description_msg(alert_description));
}

static gboolean tls_prf(const gnutls_datum_t secret, const char *label,
                        const guint8 *seed, gsize seed_len, guint8 **output,
                        gsize output_len)
{
   gboolean ret = TRUE;

   const gsize buf_size = 128;
   const gsize sha384_output_size = 48;
   g_autofree guint8 *input = NULL;
   *output = NULL;
   g_autofree guint8 *to_digest = NULL;

   // prepare buffers
   guint8 A[sha384_output_size];
   guint8 buf_digested[sha384_output_size];

   // Validate input parameters
   if (label == NULL || seed == NULL || output == NULL || output_len <= 0) {
      fp_err("Invalid input parameters in %s", __FUNCTION__);
      return FALSE;
   }

   gsize label_len = strlen(label);
   g_assert(label_len > 0);

   // Check if seed and label fit
   if (sha384_output_size + label_len + seed_len > buf_size) {
      fp_err("Input arguments too large in %s", __FUNCTION__);
      return FALSE;
   }

   // Allocate output buffer
   *output = g_malloc0(output_len);

   // prepare input = label + seed
   gsize input_len = label_len + seed_len;
   input = g_malloc0(input_len);
   memcpy(input, label, label_len); // note the ascii encoding
   memcpy(input + label_len, seed, seed_len);

   /* prepare to_digest buffer */
   gsize to_digest_len = sizeof(A) + input_len;
   to_digest = g_malloc(to_digest_len);

   // Initialize A to the first input
   memset(A, 0, sizeof(A));

   // update A with first hash
   GNUTLS_CHECK(gnutls_hmac_fast(GNUTLS_MAC_SHA384, secret.data, secret.size,
                                 input, input_len, A));

   gsize output_offset = 0;
   while (output_offset < output_len) {

      // Prepare to_digest buffer
      memcpy(to_digest, A, sizeof(A));
      memcpy(to_digest + sizeof(A), input, input_len);

      // update output
      GNUTLS_CHECK(gnutls_hmac_fast(GNUTLS_MAC_SHA384, secret.data, secret.size,
                                    to_digest, to_digest_len, buf_digested));

      gsize remains_to_write = output_len - output_offset;
      gsize to_write = remains_to_write < sha384_output_size
                           ? remains_to_write
                           : sha384_output_size;
      g_assert(output_offset + to_write <= output_len);
      memcpy(*output + output_offset, buf_digested, to_write);
      output_offset += to_write;

      // update A
      GNUTLS_CHECK(gnutls_hmac_fast(GNUTLS_MAC_SHA384, secret.data, secret.size,
                                    A, sizeof(A), A));
   }

error:
   if ((!ret) && (*output != NULL)) {
      g_free(*output);
      *output = NULL;
   }
   return ret;
}

static gboolean check_server_finished_verify_data(FpiDeviceSynapticsMoc *self,
                                                  FpiByteReader *reader,
                                                  gsize recv_verify_data_size,
                                                  gboolean *is_correct)
{
   gboolean ret = TRUE;
   *is_correct = FALSE;
   const guint sha256_size = 32;
   guint8 sent_messages_sha256[sha256_size];

   const gsize verify_data_size = 12;
   g_autofree guint8 *verify_data = NULL;
   g_autofree guint8 *recv_verify_data = NULL;

   // sizes should match
   if (recv_verify_data_size != verify_data_size) {
      fp_err("Received server finished with unexpected length: %lu, while "
             "expected was %lu",
             recv_verify_data_size, verify_data_size);
      return ret;
   }

   fpi_byte_reader_dup_data(reader, verify_data_size, &recv_verify_data);

#ifdef TLS_DEBUG
   fp_dbg("Server finished sent messages:");
   print_array(self->tls.sent_data, self->tls.sent_data_size);
#endif

   GNUTLS_CHECK(gnutls_hash_fast(
       GNUTLS_DIG_SHA256, self->tls.sent_handshake_msgs,
       self->tls.sent_handshake_msgs_size, sent_messages_sha256));
#ifdef TLS_DEBUG
   fp_dbg("Handshake finished sent messages hash:");
   print_array(sent_messages_sha256, sizeof(sent_messages_sha256));
#endif

   BOOL_CHECK(tls_prf(self->tls.master_secret, "server finished",
                      sent_messages_sha256, sha256_size, &verify_data,
                      verify_data_size));

#ifdef TLS_DEBUG
   fp_dbg("tls prf server finished output:");
   print_array(verify_data, verify_data_size);
#endif

   if (0 == memcmp(verify_data, recv_verify_data, verify_data_size)) {
      *is_correct = TRUE;
      fp_dbg("Server finished verify data match");
   } else {
      fp_err("Server finished verify data do NOT match");
      fp_err("Got:");
      print_array(recv_verify_data, recv_verify_data_size);
      fp_err("Expected:");
      print_array(verify_data, verify_data_size);
   }

error:
   return ret;
}

static gboolean parse_certificate(guint8 *data, gsize len, sensor_cert_t *cert)
{
   if (len != 400) {
      fp_err("Received certificate with incorrect length: %lu", len);
      return FALSE;
   }

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, data, len);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &cert->magic);
   g_assert(cert->magic == 0x5F3F);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &cert->curve);
   g_assert(cert->curve == 23);

   /* memcpy as we use variable length arrays for storage */
   g_assert(sizeof(cert->pubkey_x) == CERTIFICATE_KEY_SIZE);
   const guint8 *pubkey_x_data;
   read_ok &= fpi_byte_reader_get_data(&reader, sizeof(cert->pubkey_x),
                                       &pubkey_x_data);
   memcpy(cert->pubkey_x, pubkey_x_data, sizeof(cert->pubkey_x));

   g_assert(sizeof(cert->pubkey_y) == CERTIFICATE_KEY_SIZE);
   const guint8 *pubkey_y_data;
   read_ok &= fpi_byte_reader_get_data(&reader, sizeof(cert->pubkey_y),
                                       &pubkey_y_data);
   memcpy(cert->pubkey_y, pubkey_y_data, sizeof(cert->pubkey_y));

   read_ok &= fpi_byte_reader_skip(&reader, 1);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &cert->cert_type);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &cert->sign_size);
   read_ok &=
       fpi_byte_reader_dup_data(&reader, cert->sign_size, &cert->sign_data);

   return read_ok;
}

static gboolean get_client_hello_record(FpiDeviceSynapticsMoc *self,
                                        hello_t *client_hello, record_t *record)
{
   if (client_hello == NULL || record == NULL) {
      fp_err("Function %s received NULL", __FUNCTION__);
      goto error;
   }

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
   written &=
       fpi_byte_writer_put_uint8(&writer, sizeof(client_hello->session_id));
   written &= fpi_byte_writer_put_data(&writer, client_hello->session_id,
                                       sizeof(client_hello->session_id));

   /* write cipher cuites */
   guint16 cipher_suite_id_list_total_len =
       client_hello->cipher_suit_cnt * sizeof(guint16);
   written &=
       fpi_byte_writer_put_uint16_be(&writer, cipher_suite_id_list_total_len);
   for (int i = 0; i < client_hello->cipher_suit_cnt; ++i) {
      written &= fpi_byte_writer_put_uint16_be(
          &writer, client_hello->cipher_suits[i].id);
   }

   /* write compression methods - these are unsupported, so write 0
    * NOTE: The windows driver does not advertise the NULL compression
    * method.
    */
   written &= fpi_byte_writer_put_uint8(&writer, 0);

   /* write extensions
    * NOTE: The developers did not give the extensions field a length value.
    */
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

gboolean get_remote_tls_status(FpiDeviceSynapticsMoc *self, gboolean *status,
                               GError *error)
{
   FpiUsbTransfer *transfer = fpi_usb_transfer_new(FP_DEVICE(self));

   fpi_usb_transfer_fill_control(
       transfer, G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
       G_USB_DEVICE_REQUEST_TYPE_VENDOR, G_USB_DEVICE_RECIPIENT_DEVICE,
       REQUEST_TLS_SESSION_STATUS, 0, 0, TLS_SESSION_STATUS_DATA_RESP_LEN);

   transfer->short_is_error = TRUE;
   fpi_usb_transfer_submit_sync(transfer, TLS_SESSION_STATUS_TIMEOUT_MS,
                                &error);

   if (error) {
      goto error;
   }

   g_assert(transfer->actual_length >= 1);

   *status = FP_READ_UINT8(transfer->buffer) != 0;
   fp_dbg("Remote TLS session status: %s",
          *status ? "established" : "not established");

   fpi_usb_transfer_unref(transfer);
   return TRUE;
error:
   fpi_usb_transfer_unref(transfer);
   g_error("Error in function %s: %d aka '%s'", __FUNCTION__, error->code,
           error->message);
   return FALSE;
}

static void update_handshake_messages_data(FpiDeviceSynapticsMoc *self,
                                           const guint8 *data, const gsize size)
{
   // NOTE: do not update with finished messages
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
   print_array(self->tls.sent_data, self->tls.sent_data_size);
#endif
}

static void update_handshake_messages_data_record(FpiDeviceSynapticsMoc *self,
                                                  const record_t *rec)
{
   // windows driver does not update with HS_FINISHED messages
   if (rec->msg[0] != HS_FINISHED) {
      update_handshake_messages_data(self, rec->msg, rec->msg_len);
   }
}

static gboolean send_tls(FpiDeviceSynapticsMoc *self,
                         const record_t *send_records,
                         const guint send_record_cnt, guint8 **recv_data,
                         gsize *recv_size, gboolean with_hs_header,
                         GError *error)
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
                                       recv_size, FALSE));

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

static gboolean init_client_hello(FpiDeviceSynapticsMoc *self,
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
   print_array(serialized_timestamp, sizeof(client_hello->current_timestamp));
   fp_dbg("\trand:");
   print_array(client_hello->random, sizeof(client_hello->random));
#endif

   /* copy session id from self */
   g_assert(self->tls.session_id != NULL);
   memcpy(&client_hello->session_id, self->tls.session_id,
          sizeof(client_hello->session_id));

   /* TODO: changeme - add cupported ciphersuites to self
    * Set cipher suites to 0xC02E, as others seem to not work
    * -> for now hardcode everything per this
    * */
   client_hello->cipher_suit_cnt = 1;
   client_hello->cipher_suits = &tls_ecdh_ecdsa_with_aes_256_gcm_sha384;
   client_hello->extension_cnt = 2;
   client_hello->extensions =
       g_malloc(client_hello->extension_cnt * sizeof(extension_t));
   memcpy(&client_hello->extensions[0], &supported_groups, sizeof(extension_t));
   memcpy(&client_hello->extensions[1], &ec_point_formats, sizeof(extension_t));

   return TRUE;
   // error:
   //    if (client_hello->extensions != NULL) {
   //       g_free(client_hello->extensions);
   //    }
   //    return FALSE;
}

static gboolean parse_and_process_server_hello(FpiDeviceSynapticsMoc *self,
                                               FpiByteReader *reader,
                                               const guint32 read_len)
{
   g_assert(self != NULL && reader != NULL);

   gboolean read_ok = TRUE;
   guint32 read_start_pos = fpi_byte_reader_get_pos(reader);

   // TODO: what to do with these
   /* read major and minor server version */
   guint8 version_major;
   read_ok &= fpi_byte_reader_get_uint8(reader, &version_major);
   guint8 version_minor;
   read_ok &= fpi_byte_reader_get_uint8(reader, &version_minor);

   /* read current time and server random */
   const guint8 *recv_random = NULL;
   read_ok &= fpi_byte_reader_get_data(reader, sizeof(self->tls.server_random),
                                       &recv_random);
   if (read_ok) {
      memcpy(&self->tls.server_random, recv_random,
             sizeof(self->tls.server_random));
#ifdef TLS_DEBUG
      fp_dbg("received server_random:");
      print_array(recv_random, sizeof(self->tls.server_random));
#endif
   }

   /* read session id */
   read_ok &= fpi_byte_reader_get_uint8(reader, &self->tls.session_id_len);
   // TODO: this needs to be g_freed somewhere
   read_ok &= fpi_byte_reader_dup_data(reader, self->tls.session_id_len,
                                       &self->tls.session_id);

   /* read cipher cuites */
   read_ok &= fpi_byte_reader_get_uint16_be(reader, &self->tls.ciphersuit);
   /* read compression method */
   read_ok &= fpi_byte_reader_get_uint8(reader, &self->tls.compression_method);

   /* nothing else seems to be sent*/

   guint32 read_end_pos = fpi_byte_reader_get_pos(reader);
   if (read_end_pos - read_start_pos != read_len) {
      read_ok = FALSE;
      fp_err("Error occured while reading server hello");
      fp_err("\tstarted at: %d, ended at: %d, expected end: %d", read_start_pos,
             read_end_pos, read_start_pos + read_len);
   }

   return read_ok;
}

static gboolean parse_and_process_handshake_record(FpiDeviceSynapticsMoc *self,
                                                   record_t *record)
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
         BOOL_CHECK(parse_and_process_server_hello(self, &reader, msg_len));
         break;
      case HS_CERTIFICATE_REQUEST:
         fp_dbg("received certificate request");
         g_assert(msg_len == 4);
         guint32 certificate_type = 0;
         read_ok &= fpi_byte_reader_get_uint32_be(&reader, &certificate_type);
         fp_dbg("Requested certificate of type: 0x%x", certificate_type);

         // FIXME: parsed in a wrong way
         // Others not implemented
         // g_assert(certificate_type == TLS_CERT_TYPE_ECDSA_SIGN);
         self->tls.handshake_state = TLS_HANDSHAKE_END;
         break;

      case HS_SERVER_HELLO_DONE:
         fp_dbg("received server hello done");
         if (self->tls.handshake_state != TLS_HANDSHAKE_END) {
            fp_err("I did something wrong and tls state is: %d",
                   self->tls.handshake_state);
            ret = FALSE;
            self->tls.handshake_state = TLS_HANDSHAKE_END;
         }
         cont = FALSE;
         break;

      case HS_FINISHED:
         fp_dbg("received handshake finished");
         if (self->tls.handshake_state != TLS_HANDSHAKE_END) {
            fp_err("Unexpected recieval of handshake finished message - "
                   "handshake state is %d",
                   self->tls.handshake_state);
            ret = FALSE;
         }
         gboolean verify_matches = FALSE;
         BOOL_CHECK(check_server_finished_verify_data(self, &reader, msg_len,
                                                      &verify_matches));
         if (!verify_matches) {
            fp_dbg("Server verify message does not match");
            ret = FALSE;
            goto error;
         }
         fp_dbg("Server verify message matches");
         self->tls.established = TRUE;
         self->tls.handshake_state = TLS_HANDSHAKE_FINISHED;
         cont = FALSE;
         break;

      default:
         fp_err("Received unimplemented msg type: %d", msg_type);
         ret = FALSE;
      }

      if (!read_ok) {
         fp_err("Error while reading message header from record");
         ret = FALSE;
         goto error;
      }
   }

error:
   return ret;
}

static gboolean parse_and_process_records(FpiDeviceSynapticsMoc *self,
                                          guint8 *data, gsize data_len)
{
   FpiByteReader reader;
   gboolean read_ok = TRUE;
   gboolean ret = TRUE;
   fpi_byte_reader_init(&reader, data, data_len);

   record_t record;
   while ((fpi_byte_reader_get_remaining(&reader) != 0) && read_ok) {
      record.msg = NULL;
      /* parse record header */
      read_ok &= fpi_byte_reader_get_uint8(&reader, &record.type);
      read_ok &= fpi_byte_reader_get_uint8(&reader, &record.version_major);
      read_ok &= fpi_byte_reader_get_uint8(&reader, &record.version_minor);
      read_ok &= fpi_byte_reader_get_uint16_be(&reader, &record.msg_len);
      read_ok &= fpi_byte_reader_dup_data(&reader, record.msg_len, &record.msg);
      if (!read_ok) {
         fp_err("Transfer in version response to version query was too short");
         goto error;
      }

      if (self->tls.remote_sends_encrypted) {
         guint8 *ptext = NULL;
         gsize ptext_size = 0;
         BOOL_CHECK(decrypt_record(self, &record, &ptext, &ptext_size));
         g_free(record.msg);
         record.msg = ptext;
         record.msg_len = ptext_size;
      }

      fp_dbg("%s received record:", __FUNCTION__);
      fp_dbg("\tMsg type: 0x%x", record.type);
      fp_dbg("\tVersion: %d.%d", record.version_major, record.version_minor);
      fp_dbg("\tData len: %d", record.msg_len);
      // TODO: check for record version

      switch (record.type) {
      case RECORD_TYPE_CHANGE_CIPHER_SPEC:
         fp_dbg("change cipher spec received - enabling remote decryption");
         self->tls.remote_sends_encrypted = TRUE;
         break;
      case RECORD_TYPE_HANDSHAKE:
         update_handshake_messages_data_record(self, &record);
         BOOL_CHECK(parse_and_process_handshake_record(self, &record));
         break;
      case RECORD_TYPE_ALERT:;
         guint8 alert_level = record.msg[0];
         guint8 alert_description = record.msg[1];
         if (alert_level == TLS_ALERT_LVL_WARNING &&
             alert_description == TLS_ALERT_DESC_CLOSE_NOTIFY) {
            fp_dbg("Remote confirmed TLS session close");
            self->tls.remote_sends_encrypted = FALSE;
            self->tls.established = FALSE;
         } else {
            log_tls_alert_msg(alert_level, alert_description);
         }
         self->tls.handshake_state = TLS_HANDSHAKE_ALERT;
         goto error;

         break;
      default:
         fp_err("Got unimplemented record type: %d", record.type);
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

static gboolean append_client_certificate(FpiDeviceSynapticsMoc *self,
                                          FpiByteWriter *writer)
{
   gboolean written = TRUE;

   /* add header */
   written &= fpi_byte_writer_put_uint8(writer, HS_CERTIFICATE);
   /* 8 = 2*3 (for size) + 2 (for padding?) */
   guint32 cert_msg_size = 8 + self->pairing_data.host_cert_bytes_len;
   written &= fpi_byte_writer_put_uint24_be(writer, cert_msg_size);

   /* add size twice for some reason*/
   written &= fpi_byte_writer_put_uint24_be(
       writer, self->pairing_data.host_cert_bytes_len);
   written &= fpi_byte_writer_put_uint24_be(
       writer, self->pairing_data.host_cert_bytes_len);
   /* add the padding? */
   written &= fpi_byte_writer_put_uint16_be(writer, 0);

   /* add the certificate itself*/
   written &=
       fpi_byte_writer_put_data(writer, self->pairing_data.host_cert_bytes,
                                self->pairing_data.host_cert_bytes_len);

   return written;
}

static gboolean
append_client_key_exchange_to_record(FpiByteWriter *writer,
                                     const gnutls_privkey_t *privkey)
{
   gboolean ret = TRUE;

   /* add header */
   ret &= fpi_byte_writer_put_uint8(writer, HS_CLIENT_KEY_EXCHANGE);
   guint32 msg_size = 1 + 32 + 32; // format + sizeof(x) + sizeof(y)
   ret &= fpi_byte_writer_put_uint24_be(writer, msg_size);

   /* get public key */
   gnutls_pubkey_t pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&pubkey));

   // the flag GNUTLS_KEY_DIGITAL_SIGNATURE is a guess
   GNUTLS_CHECK(gnutls_pubkey_import_privkey(pubkey, *privkey,
                                             GNUTLS_KEY_DIGITAL_SIGNATURE, 0));

   gnutls_datum_t x;
   gnutls_datum_t y;
   GNUTLS_CHECK(gnutls_pubkey_export_ecc_raw(pubkey, NULL, &x, &y));
   gnutls_pubkey_deinit(pubkey);

#ifdef TLS_DEBUG
   fp_dbg("exported pubkey");
   fp_dbg("\tx");
   print_array(x.data, x.size);
   fp_dbg("\ty");
   print_array(y.data, y.size);
#endif

   /* uncompressed format */
   guint x_offset = x.size - 32;
   guint y_offset = y.size - 32;

#ifdef TLS_DEBUG
   if (x_offset != 0) {
      fp_dbg("x point data before:");
      print_array(x.data, x.size);
      fp_dbg("x point data after:");
      print_array(x.data + x_offset, 32);
      printf("\n");
   }
   if (y_offset != 0) {
      fp_dbg("y size if %d > 32 -> offset = %d", y.size, y_offset);
      fp_dbg("y point data before:");
      print_array(y.data, y.size);
      fp_dbg("y point data after:");
      print_array(y.data + y_offset, 32);
      printf("\n");
   }
#endif

   ret &= fpi_byte_writer_put_uint8(writer, 0x4);
   ret &= fpi_byte_writer_put_data(writer, x.data + x_offset, 32);
   ret &= fpi_byte_writer_put_data(writer, y.data + y_offset, 32);

error:
   if (x.data != NULL) {
      g_free(x.data);
   }
   if (y.data != NULL) {
      g_free(y.data);
   }

   return ret;
}

static gboolean append_certificate_verify_to_record(FpiDeviceSynapticsMoc *self,
                                                    FpiByteWriter *writer)
{
   gboolean ret = TRUE;
   const int sha256_size = 32;
   gnutls_datum_t signature = {.data = NULL, .size = 0};

   guint8 sent_messages_sha256[sha256_size];
   gnutls_datum_t sent_messages_sha256_datum = {.data = sent_messages_sha256,
                                                .size = sha256_size};

#ifdef TLS_DEBUG
   fp_dbg("Messages to certificate veify");
   print_array(self->tls.sent_data, self->tls.sent_data_size);
#endif

   GNUTLS_CHECK(gnutls_hash_fast(
       GNUTLS_DIG_SHA256, self->tls.sent_handshake_msgs,
       self->tls.sent_handshake_msgs_size, &sent_messages_sha256));

#ifdef TLS_DEBUG
   fp_dbg("Siging hash:");
   print_array(sent_messages_sha256, sha256_size);
#endif

   GNUTLS_CHECK(gnutls_privkey_sign_hash2(
       self->pairing_data.private_key, GNUTLS_SIGN_ECDSA_SHA256, 0,
       &sent_messages_sha256_datum, &signature));

#ifdef TLS_DEBUG
   fp_dbg("Signature:");
   print_array(signature.data, signature.size);
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

static gboolean encrypt_record(FpiDeviceSynapticsMoc *self,
                               record_t *record_to_encrypt, guint8 **ctext,
                               gsize *ctext_len)
{
#ifdef TLS_DEBUG
   printf("Encrypting record msg:\n");
   print_array(record_to_encrypt->msg, record_to_encrypt->msg_len);
#endif

   gboolean ret = TRUE;
   gboolean crypt_initialized = FALSE;

   gnutls_datum_t gcm_iv = {.data = NULL, .size = 0};

   // Setup storage for additional data
   gsize additional_data_size =
       sizeof(self->tls.encrypt_seq_num) + RECORD_HEADER_SIZE;
   guint8 additional_data[additional_data_size];

   // create random nonce
   guint64 nonce;
   GNUTLS_CHECK(gnutls_rnd(GNUTLS_RND_NONCE, &nonce, sizeof(nonce)));

   // create GCM IV = encryption_iv + nonce
   g_assert(self->tls.encryption_iv.size != 0);
   gcm_iv.size = sizeof(nonce) + self->tls.encryption_iv.size;
   gcm_iv.data = g_malloc(gcm_iv.size * sizeof(*gcm_iv.data));
   memcpy(gcm_iv.data, self->tls.encryption_iv.data,
          self->tls.encryption_iv.size);
   FP_WRITE_UINT64_BE(gcm_iv.data + self->tls.encryption_iv.size, nonce);

#ifdef TLS_DEBUG
   fp_dbg("\nEncryption nonce: %lu", nonce);
   fp_dbg("\nEncryption IV:");
   print_array(self->tls.encryption_iv.data, self->tls.encryption_iv.size);
   fp_dbg("GCM IV:");
   print_array(gcm_iv.data, gcm_iv.size);
   fp_dbg("Encryption key:");
   print_array(self->tls.encryption_key.data, self->tls.encryption_key.size);
#endif

   // Initialize GCM cipher
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
   g_assert(written); // NOTE: this should have no way of failing

#ifdef TLS_DEBUG
   fp_dbg("Encryption - auth data:");
   print_array(additional_data, additional_data_size);
#endif

   // TODO: check - maximul encrypted size = plaintext_size + tag_size
   // Allocate for result
   gsize allocated_for_ctext = record_to_encrypt->msg_len + self->tls.tag_size;
   gsize to_allocate = sizeof(nonce) + allocated_for_ctext;
   *ctext = g_malloc(to_allocate);

   // add nonce to output
   FP_WRITE_UINT64_BE(*ctext, nonce);

   // Encrypt text
   GNUTLS_CHECK(gnutls_aead_cipher_encrypt(
       aead_hd, gcm_iv.data, gcm_iv.size, additional_data, additional_data_size,
       self->tls.tag_size, record_to_encrypt->msg, record_to_encrypt->msg_len,
       (*ctext) + sizeof(nonce), &allocated_for_ctext));

   // Set encrypted text size (encryption may be shorter)
   *ctext_len = sizeof(nonce) + allocated_for_ctext;

   self->tls.encrypt_seq_num += 1;

#ifdef TLS_DEBUG
   printf("Encrypted:\n");
   print_array(*ctext, *ctext_len);
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

static gboolean
append_encrypted_handshake_finish_to_record(FpiDeviceSynapticsMoc *self,
                                            FpiByteWriter *writer)
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
   print_array(self->tls.sent_data, self->tls.sent_data_size);
#endif

   GNUTLS_CHECK(gnutls_hash_fast(
       GNUTLS_DIG_SHA256, self->tls.sent_handshake_msgs,
       self->tls.sent_handshake_msgs_size, sent_messages_sha256));
#ifdef TLS_DEBUG
   fp_dbg("Handshake finished sent messages hash:");
   print_array(sent_messages_sha256, sizeof(sent_messages_sha256));
#endif

   BOOL_CHECK(tls_prf(self->tls.master_secret, "client finished",
                      sent_messages_sha256, sha256_size, &tls_prf_output,
                      prf_size));

#ifdef TLS_DEBUG
   fp_dbg("tls prf client finished output:");
   print_array(tls_prf_output, prf_size);
#endif

   // Get data to encrypt
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

   BOOL_CHECK(
       encrypt_record(self, &record_to_encrypt, &encrypted, &encrypted_size));

   // Append to record data
   ret &= fpi_byte_writer_put_data(writer, encrypted, encrypted_size);

error:
   return ret;
}

static gboolean generate_and_store_aead_keys(FpiDeviceSynapticsMoc *self)
{
   gboolean ret = TRUE;
   g_autofree guint8 *data = NULL;

   gsize key_size = self->tls.encryption_key.size;
   if (!tls_prf(self->tls.master_secret, "key expansion",
                self->tls.derive_input, sizeof(self->tls.derive_input), &data,
                4 * key_size)) {
      ret = FALSE;
      goto error;
   }

#ifdef TLS_DEBUG
   printf("key expansion data:\n");
   print_array(data, 4 * key_size);
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

static gboolean tls_aead_encryption_algorithm_init(FpiDeviceSynapticsMoc *self)
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

   ret = generate_and_store_aead_keys(self);
   return TRUE;

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
      free(*serialized);
   }

   return ret;
}

gboolean tls_wrap(FpiDeviceSynapticsMoc *self, guint8 *ptext, gsize ptext_size,
                  guint8 **ctext, gsize *ctext_size)
{
   gboolean ret = TRUE;
   gboolean written = TRUE;
   guint8 *encrypted_msg = NULL;

   if (!self->tls.established) {
      g_warning("Calling wrap while tls is not established");
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

   guint8 *encrypted_record = NULL;
   gsize encrypted_record_size = 0;
   BOOL_CHECK(encrypt_record(self, &record_to_encrypt, &encrypted_record,
                             &encrypted_record_size));

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
   if (encrypted_record != NULL) {
      g_free(encrypted_record);
   }
   if (encrypted_msg != NULL) {
      g_free(encrypted_msg);
   }
   return ret;
}

gboolean tls_unwrap(FpiDeviceSynapticsMoc *self, guint8 *ctext,
                    gsize ctext_size, guint8 **ptext, gsize *ptext_size)
{
   gboolean ret = TRUE;

   if (!self->tls.established) {
      g_warning("Calling unwrap while tls is not established");
      *ptext = ctext;
      *ptext_size = ctext_size;
      return ret;
   }

   record_t encrypted_record = {0};
   BOOL_CHECK(read_record(ctext, ctext_size, &encrypted_record));

   BOOL_CHECK(decrypt_record(self, &encrypted_record, ptext, ptext_size));

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

gboolean tls_close_session(FpiDeviceSynapticsMoc *self, GError *error)
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
   msg[0] = TLS_ALERT_LVL_WARNING;
   msg[1] = TLS_ALERT_DESC_CLOSE_NOTIFY;
   record_to_encrypt.msg = msg;

   gsize encrypted_size = 0;
   BOOL_CHECK(
       encrypt_record(self, &record_to_encrypt, &encrypted, &encrypted_size));

   // turn if off now, as we do not want the encrypted command to be wrapped
   self->tls.established = FALSE;

   const gsize send_size = RECORD_HEADER_SIZE + encrypted_size;
   send_data = g_malloc(send_size);

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   written &= write_record_header(&writer, &record_to_encrypt);
   written &= fpi_byte_writer_put_uint16_be_inline(&writer, encrypted_size);
   written &= fpi_byte_writer_put_data(&writer, encrypted, encrypted_size);
   WRITTEN_CHECK(written);

   gsize recv_data_size = 256;
   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_data_size, FALSE));

   BOOL_CHECK(parse_and_process_records(self, recv_data, recv_data_size));

error:
   return ret;
}

/* Establish session funcitons =============================================
 */

static gboolean tls_handshake_state_prepare(FpiDeviceSynapticsMoc *self)
{
   gboolean ret = TRUE;

   self->tls.version_major = TLS_PROTOCOL_VERSION_MAJOR;
   self->tls.version_minor = TLS_PROTOCOL_VERSION_MINOR;
   self->tls.session_id_len = TLS_SESSION_ID_LEN;
   self->tls.session_id = g_malloc0(self->tls.session_id_len);
   self->tls.remote_sends_encrypted = FALSE;

   self->tls.handshake_state += 1; // TLS_HANDSHAKE_START

error:
   return ret;
}

gboolean load_sample_pairing_data(FpiDeviceSynapticsMoc *self)
{
   gboolean ret = TRUE;

   /* load sample certificates for now */
   self->pairing_data.sensor_cert_bytes = sample_sensor_cert;
   self->pairing_data.sensor_cert_bytes_len = sizeof(sample_sensor_cert);

   BOOL_CHECK(parse_certificate(self->pairing_data.sensor_cert_bytes,
                                self->pairing_data.sensor_cert_bytes_len,
                                &self->pairing_data.sensor_cert));

   self->pairing_data.host_cert_bytes = sample_recv_host_cert;
   self->pairing_data.host_cert_bytes_len = sizeof(sample_recv_host_cert);

   BOOL_CHECK(parse_certificate(self->pairing_data.host_cert_bytes,
                                self->pairing_data.host_cert_bytes_len,
                                &self->pairing_data.host_cert));
   fp_dbg("Private key import success");

   GNUTLS_CHECK(gnutls_privkey_init(&self->pairing_data.private_key));

   /* load sample private key for now */
   GNUTLS_CHECK(gnutls_privkey_import_ecc_raw(
       self->pairing_data.private_key, GNUTLS_ECC_CURVE_SECP256R1,
       &sample_privkey_x_datum, &sample_privkey_y_datum,
       &sample_privkey_k_datum));

   GNUTLS_CHECK(gnutls_privkey_verify_params(self->pairing_data.private_key));

   self->pairing_data.present = TRUE;

error:
   return ret;
}

static gboolean tls_handshake_state_start(FpiDeviceSynapticsMoc *self,
                                          GError *error)
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

   if (!parse_and_process_records(self, recv_data, recv_data_size)) {
      goto error;
   }

   self->tls.handshake_state = TLS_HANDSHAKE_END;

error:
   if (client_hello_record.msg != NULL) {
      g_free(client_hello_record.msg);
   }
   if (client_hello.extensions != NULL) {
      g_free(client_hello.extensions);
   }
   return ret;
}

static gboolean calculate_premaster_secret(FpiDeviceSynapticsMoc *self,
                                           gnutls_privkey_t privkey,
                                           gnutls_datum_t *premaster_secret)
{
   gboolean ret = TRUE;
   gboolean pubkey_initialized = FALSE;

   /* get sensor pubkey */
   gnutls_pubkey_t sensor_pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&sensor_pubkey));

   pubkey_initialized = TRUE;

   g_assert(self->pairing_data.sensor_cert.curve == 23);

   // NOTE: the keys are stored in little endian - reverse them as gnutls seems
   // to expect big endian
   // count_trailing_zeros(pubkey_x.data, pubkey_x.size);
   gnutls_datum_t pubkey_x = {.size = 32,
                              .data = self->pairing_data.sensor_cert.pubkey_x};
   reverse_array(pubkey_x.data, pubkey_x.size);

   gnutls_datum_t pubkey_y = {.size = 32,
                              .data = self->pairing_data.sensor_cert.pubkey_y};
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

static gboolean calculate_master_secret(FpiDeviceSynapticsMoc *self,
                                        gnutls_privkey_t privkey)
{
   gboolean ret = TRUE;

   gnutls_datum_t premaster_secret = {.data = NULL, .size = 0};
   BOOL_CHECK(calculate_premaster_secret(self, privkey, &premaster_secret));

#ifdef TLS_DEBUG
   fp_dbg("premaster_secret:");
   print_array(premaster_secret.data, premaster_secret.size);
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
   print_array(premaster_secret.data, premaster_secret.size);
   fp_dbg("\tseed:");
   print_array(self->tls.derive_input, sizeof(self->tls.derive_input));
#endif

   ret &= tls_prf(premaster_secret, "master secret", self->tls.derive_input,
                  sizeof(self->tls.derive_input), &self->tls.master_secret.data,
                  self->tls.master_secret.size);
#ifdef TLS_DEBUG
   fp_dbg("master_secret:");
   print_array(self->tls.master_secret.data, self->tls.master_secret.size);
#endif

error:
   if (premaster_secret.data != NULL) {
      g_free(premaster_secret.data);
   }
   return ret;
}

static gboolean tls_handshake_state_end(FpiDeviceSynapticsMoc *self,
                                        GError *error)
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
   print_array(x.data, x.size);
   fp_dbg("\ty");
   print_array(y.data, y.size);
   fp_dbg("\tk");
   print_array(k.data, k.size);
#endif

   gsize client_kex_pos_before = fpi_byte_writer_get_pos(&writer);
   written &= append_client_key_exchange_to_record(&writer, &privkey);
   gsize client_kex_pos_after = fpi_byte_writer_get_pos(&writer);

   /* update stored all sent msg data */
   update_handshake_messages_data(self,
                                  writer.parent.data + client_kex_pos_before,
                                  client_kex_pos_after - client_kex_pos_before);

   gsize cert_verify_pos_before = fpi_byte_writer_get_pos(&writer);
   written &= append_certificate_verify_to_record(self, &writer);
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
   BOOL_CHECK(calculate_master_secret(self, privkey));
   BOOL_CHECK(tls_aead_encryption_algorithm_init(self));

   /* send handshake finished */
   records_to_send[2].type = RECORD_TYPE_HANDSHAKE;
   records_to_send[2].version_major = self->tls.version_major;
   records_to_send[2].version_minor = self->tls.version_minor;

   fpi_byte_writer_init(&writer);
   written &= append_encrypted_handshake_finish_to_record(self, &writer);
   records_to_send[2].msg_len = fpi_byte_writer_get_pos(&writer);
   records_to_send[2].msg = fpi_byte_writer_reset_and_get_data(&writer);

   if (!written) {
      fp_err("%s: error while writing third part", __FUNCTION__);
   }

   WRITTEN_CHECK(written);

   gsize recv_size;
   BOOL_CHECK(
       send_tls(self, records_to_send, 3, &recv_data, &recv_size, TRUE, error));

   BOOL_CHECK(parse_and_process_records(self, recv_data, recv_size));

   self->tls.handshake_state = TLS_HANDSHAKE_FINISHED;

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

gboolean establish_tls_session(FpiDeviceSynapticsMoc *self, GError *error)
{
   gboolean ret = TRUE;
   fp_dbg("Establishing TLS session");

   gboolean remote_established = FALSE;
   BOOL_CHECK(get_remote_tls_status(self, &remote_established, error));
   remote_established = FALSE;

   /*handle possible combinations*/
   if (self->tls.established && remote_established) {
      fp_dbg("\thost and remote are already in session");
      return TRUE;
   } else if (self->tls.established && !remote_established) {
      fp_err("\thost is in session but device is not");
      goto error;
   } else if (!self->tls.established && remote_established) {
      fp_err("\tdevice is in session but host is not");
      goto error;
   }

   while (!self->tls.established) {
      fp_dbg("TLS handshake state: %d", self->tls.handshake_state);

      switch (self->tls.handshake_state) {
      case TLS_HANDSHAKE_PREPARE:
         fp_dbg("TLS handshake state prepare");
         if (!tls_handshake_state_prepare(self)) {
            self->tls.handshake_state = TLS_HANDSHAKE_FAILED;
            ret = FALSE;
            goto error;
         }
         break;
      case TLS_HANDSHAKE_START:
         fp_dbg("TLS handshake state: sending client hello");
         if (!tls_handshake_state_start(self, error)) {
            self->tls.handshake_state = TLS_HANDSHAKE_FAILED;
         }
         break;
      case TLS_HANDSHAKE_END:
         fp_dbg("TLS handshake state: sending certificate and key");
         if (!tls_handshake_state_end(self, error)) {
            self->tls.handshake_state = TLS_HANDSHAKE_FAILED;
         }
         self->tls.sent_handshake_msgs_alloc_size = 0;
         self->tls.sent_handshake_msgs_size = 0;
         if (self->tls.sent_handshake_msgs != NULL) {
            g_free(self->tls.sent_handshake_msgs);
         }
         break;

      case TLS_HANDSHAKE_ALERT:
         self->tls.handshake_state += 1; // TLS_HANDSHAKE_FAILED
         break;

      case TLS_HANDSHAKE_FAILED:
         self->tls.sent_handshake_msgs_alloc_size = 0;
         self->tls.sent_handshake_msgs_size = 0;
         if (self->tls.sent_handshake_msgs != NULL) {
            g_free(self->tls.sent_handshake_msgs);
         }
         self->tls.established = FALSE;
         ret = FALSE;
         goto error;
         break;

      case TLS_HANDSHAKE_FINISHED:
         // FIXME: g_free later
         // g_free(self->tls.session_id);
         self->tls.established = TRUE;
         break;

      default:
         fp_err("Unimplemented handshake state: %d", self->tls.handshake_state);
         goto error;
      }
   }
error:
   if (!ret) {
      // g_error("Error in function %s: %d aka '%s'", __FUNCTION__,
      // error->code,
      g_error("Error in function %s", __FUNCTION__);
   }
   return ret;
}

gboolean verify_sensor_certificate(FpiDeviceSynapticsMoc *self,
                                   gnutls_pubkey_t sensor_pubkey)
{
   gboolean ret = TRUE;
   gboolean pubkey_initialized = FALSE;

   /* get public key */
   gnutls_pubkey_t pubkey;
   GNUTLS_CHECK(gnutls_pubkey_init(&pubkey));
   pubkey_initialized = TRUE;

   // the flag GNUTLS_KEY_DIGITAL_SIGNATURE is a guess
   GNUTLS_CHECK(gnutls_pubkey_import_privkey(pubkey,
                                             self->pairing_data.private_key,
                                             GNUTLS_KEY_DIGITAL_SIGNATURE, 0));

   // TODO: think of a name for teh constant
   // everything up to signature size
   gnutls_datum_t data = {.size = 142,
                          .data = self->pairing_data.sensor_cert_bytes};
   gnutls_datum_t signature = {.size = self->pairing_data.sensor_cert.sign_size,
                               .data =
                                   self->pairing_data.sensor_cert.sign_data};

   GNUTLS_CHECK(gnutls_pubkey_verify_data2(
       sensor_pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0, &data, &signature));

error:
   if (pubkey_initialized) {
      gnutls_pubkey_deinit(pubkey);
   }
   return ret;
}
