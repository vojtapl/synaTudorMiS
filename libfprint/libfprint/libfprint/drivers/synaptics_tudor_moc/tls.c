/*
 * TODO: header
 */

#include "communication.h"
#include "device.h"
#include "drivers_api.h"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-usb-transfer.h"
#include "gnutls/abstract.h"
#include "sample_pairing_data.h"
#include "tls.h"
#include <gio/gio.h>
#include <glib.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

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
#define BOOL_CHECK(func_call)                                                  \
   do {                                                                        \
      gboolean func_ret = (func_call);                                         \
      if (!func_ret) {                                                         \
         fp_err("Error in " #func_call);                                       \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)
#define WRITTEN_CHECK(condition)                                               \
   do {                                                                        \
      if (!(condition)) {                                                      \
         fp_err("Writing error occurred in %s", __FUNCTION__);                 \
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

static void reverse_array(guint8 *arr, gsize size)
{
   gint start = 0;
   gint end = size - 1;
   gint temp;

   while (start < end) {
      // Swap the elements at start and end
      temp = arr[start];
      arr[start] = arr[end];
      arr[end] = temp;

      // Move towards the middle
      start++;
      end--;
   }
}

static void print_array(const guint8 *arr, const gint size)
{
   for (int i = 0; i < size; i++) {
      printf("%02x", arr[i]);
   }
   printf("\n"); // Print a newline at the end
}

static guint count_trailing_zeros(guint8 *array, gsize length)
{
   int count = 0;

   for (gint i = length - 1; i >= 0; --i) {
      if (array[i] == 0x00) {
         count++;
      } else {
         break; // Stop counting when a non-zero byte is found
      }
   }

   return count;
}

static gboolean decrypt_record(FpiDeviceSynapticsMoc *self,
                               record_t *record_to_decrypt, guint8 **ptext,
                               gsize *ptext_len)
{
   printf("Decrypting record msg:\n");
   print_array(record_to_decrypt->msg, record_to_decrypt->msg_len);

   gboolean ret = TRUE;
   gboolean crypt_initialized = FALSE;
   // type_id (1) + tls_protocol_version (2) + length (2)

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
   gnutls_datum_t gcm_iv;
   g_assert(self->tls.decryption_iv.size != 0);
   gcm_iv.size = sizeof(nonce) + self->tls.decryption_iv.size;
   gcm_iv.data = g_malloc(gcm_iv.size * sizeof(*gcm_iv.data));
   memcpy(gcm_iv.data, self->tls.decryption_iv.data,
          self->tls.decryption_iv.size);
   FP_WRITE_UINT64_BE(gcm_iv.data + self->tls.decryption_iv.size, nonce);

   // TODO: debug start
   fp_dbg("\ndecryption nonce: %lu", nonce);
   fp_dbg("\ndecryption IV:");
   print_array(self->tls.decryption_iv.data, self->tls.decryption_iv.size);
   fp_dbg("GCM IV:");
   print_array(gcm_iv.data, gcm_iv.size);
   fp_dbg("dectyption key:");
   print_array(self->tls.decryption_key.data, self->tls.decryption_key.size);
   // TODO: debug end

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
   written &= fpi_byte_writer_put_uint8(&writer, record_to_decrypt->type);
   written &=
       fpi_byte_writer_put_uint8(&writer, record_to_decrypt->version_major);
   written &=
       fpi_byte_writer_put_uint8(&writer, record_to_decrypt->version_minor);
   written &= fpi_byte_writer_put_uint16_be(&writer, expected_ptext_len);
   g_assert(written); // NOTE: this should have no way of failing

   // Allocate for result
   gsize allocated_for_ptext = expected_ptext_len;
   *ptext = g_malloc(allocated_for_ptext);

   // TODO: debug start
   fp_dbg("Decryption - auth data:");
   print_array(additional_data, additional_data_size);
   // TODO: debug end

   // Decrypt text
   GNUTLS_CHECK(gnutls_aead_cipher_decrypt(
       aead_hd, gcm_iv.data, gcm_iv.size, additional_data, additional_data_size,
       self->tls.tag_size, ctext, ctext_len, *ptext, &allocated_for_ptext));

   // Set decrypted text size (decryption may be shorter)
   *ptext_len = allocated_for_ptext;

   self->tls.decrypt_seq_num += 1;

   printf("Decrypted:\n");
   print_array(*ptext, *ptext_len);

error:
   if (crypt_initialized) {
      gnutls_aead_cipher_deinit(aead_hd);
   }
   if (!ret && *ptext != NULL) {
      g_free(*ptext);
      *ptext = NULL;
   }

   return ret;
}

static char *tls_alert_description_msg(const guint alert_description)
{
   char *ret;
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
   fp_err("Received TLS alert level %s with description: %u aka %s",
          alert_level_msg, alert_description,
          tls_alert_description_msg(alert_description));
}

static gboolean tls_prf(const gnutls_datum_t secret, const char *label,
                        const guint8 *seed, gsize seed_len, guint8 **output,
                        gsize output_len)
{
   gboolean ret = TRUE;

   const gsize buf_size = 128;
   const gsize sha384_output_size = 48;
   guint8 *input = NULL;
   *output = NULL;
   guint8 *to_digest = NULL;

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
   if (input != NULL) {
      g_free(input);
   }
   if (to_digest != NULL) {
      g_free(to_digest);
   }
   return ret;
}
static void tls_prf_check(void)
{

   guint8 secret1[] = {
       0x19, 0x3f, 0xd4, 0xb2, 0x7c, 0x10, 0xa6, 0xd7, 0xd7, 0x99, 0xb6, 0xf9,
       0x31, 0x2c, 0xc9, 0x37, 0x5f, 0x8f, 0x00, 0xe2, 0x07, 0x2d, 0x4f, 0x31,
       0x5c, 0xd2, 0x0e, 0x50, 0x94, 0x3a, 0x5d, 0xe0, 0xfc, 0xc8, 0xe1, 0x04,
       0x39, 0xd0, 0x0a, 0xe4, 0xa0, 0x3b, 0x5a, 0xd5, 0xd3, 0x86, 0x4b, 0xfe};
   char *label1 = "key expansion";
   guint8 seed1[] = {0x66, 0xb3, 0x28, 0x0b, 0x0a, 0xe2, 0x93, 0xc6, 0x0d, 0x35,
                     0xbc, 0xb6, 0xfd, 0xac, 0x0f, 0x33, 0x15, 0x74, 0x9f, 0x65,
                     0x85, 0xe4, 0x08, 0xb7, 0xd4, 0xda, 0x44, 0xd5, 0xb4, 0x8b,
                     0x85, 0x8c, 0x00, 0x00, 0x66, 0x96, 0x42, 0xe1, 0xb5, 0x7c,
                     0x88, 0x5a, 0x1f, 0x4e, 0xc7, 0xe5, 0xea, 0x93, 0x60, 0x0f,
                     0x14, 0x47, 0xb3, 0x85, 0xfc, 0xa8, 0x37, 0x80, 0x7f, 0xb7,
                     0x04, 0x5c, 0x56, 0xcc

   };

   gsize result_len1 = 128;

   guint8 expected_result1[] = {
       0x36, 0xa7, 0xa1, 0x08, 0x92, 0x65, 0x2c, 0x62, 0x6f, 0xba, 0x1a, 0x46,
       0x4b, 0xd7, 0x2b, 0x86, 0xc7, 0xb6, 0x74, 0xbe, 0xb9, 0xab, 0x5c, 0x09,
       0x0c, 0x30, 0xc7, 0xf9, 0x98, 0xe5, 0x47, 0xfa, 0x1d, 0x04, 0xf1, 0xce,
       0x1c, 0x17, 0x20, 0x03, 0x1d, 0x9e, 0x37, 0xd4, 0x25, 0x66, 0x93, 0x1b,
       0xef, 0x54, 0x8d, 0xed, 0x0d, 0x55, 0xd2, 0xac, 0x43, 0x0c, 0x87, 0x47,
       0xba, 0x98, 0x07, 0x81, 0x1c, 0x7c, 0x00, 0x7d, 0xa3, 0x30, 0xce, 0x70,
       0x13, 0x02, 0xa4, 0x76, 0x65, 0x82, 0x67, 0x9f, 0xd3, 0x02, 0x16, 0x92,
       0x81, 0x51, 0x24, 0x2e, 0xc2, 0xb7, 0x26, 0xdd, 0x1b, 0x5b, 0x91, 0xc9,
       0x78, 0x6b, 0x0e, 0x58, 0x7b, 0x5c, 0x19, 0x2b, 0xe9, 0x66, 0x4a, 0x16,
       0x89, 0x81, 0x15, 0x25, 0x2f, 0x19, 0x12, 0xb8, 0x1d, 0xf5, 0x8d, 0xbe,
       0xa0, 0xe5, 0xd2, 0xb6, 0xb4, 0xfc, 0x5a, 0xe8

   };

   guint8 *result1 = NULL;
   gnutls_datum_t secret_datum1 = {.data = secret1, .size = sizeof(secret1)};
   g_assert(tls_prf(secret_datum1, label1, seed1, sizeof(seed1), &result1,
                    result_len1));
   // printf("expected:\n");
   // print_array(expected_result, result_len);
   // printf("got:\n");
   // print_array(result, result_len);
   g_assert(0 == memcmp(expected_result1, result1, result_len1));
   fp_dbg("tls prf test 1 OK");

   guint8 secret2[] = {0x45, 0x92, 0x78, 0xb4, 0x60, 0xae, 0x45, 0xdd,
                       0xe2, 0xee, 0xae, 0x1f, 0x5a, 0xfb, 0xe2, 0x08,
                       0x09, 0x95, 0x4e, 0x73, 0x65, 0x36, 0x5e, 0x49,
                       0xa8, 0x6f, 0x87, 0xd7, 0xfe, 0xe2, 0x02, 0x44};
   char *label2 = "master secret";
   guint8 seed2[] = {0x5a, 0xf2, 0x3d, 0x9b, 0x69, 0xb8, 0x98, 0xf4, 0x78, 0x69,
                     0x61, 0xa9, 0x0d, 0x41, 0xae, 0x67, 0x31, 0x1a, 0x1c, 0xa8,
                     0x92, 0xb4, 0x49, 0x0d, 0x0d, 0x6d, 0x32, 0x27, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x5f, 0x9c, 0x1a, 0x49, 0x60, 0x1a,
                     0xd8, 0x42, 0xbe, 0xfe, 0xb4, 0xdc, 0xe3, 0x1f, 0x01, 0xa9,
                     0x2b, 0xa8, 0x97, 0x51, 0xd2, 0x14, 0x38, 0x79, 0x9d, 0xbb,
                     0x2e, 0x86, 0x03, 0xe3};

   gsize result_len2 = 48;

   guint8 expected_result2[] = {
       0xad, 0x0a, 0x9f, 0x9f, 0xe3, 0x9d, 0x2f, 0xd7, 0xfc, 0xb2, 0x34, 0xb5,
       0xd7, 0xa3, 0x0f, 0xa1, 0x6c, 0x71, 0xec, 0x06, 0xd2, 0xc2, 0xb2, 0x6c,
       0x58, 0xd0, 0xfd, 0x61, 0x40, 0xbf, 0xab, 0x0c, 0x7f, 0xa8, 0xd7, 0x81,
       0xe0, 0x32, 0x23, 0xa2, 0x9a, 0xe4, 0x3e, 0x5c, 0xcd, 0x1a, 0x51, 0x6d};

   guint8 *result2 = NULL;
   gnutls_datum_t secret_datum2 = {.data = secret2, .size = sizeof(secret2)};
   g_assert(tls_prf(secret_datum2, label2, seed2, sizeof(seed2), &result2,
                    result_len2));
   printf("expected:\n");
   print_array(expected_result2, result_len2);
   printf("got:\n");
   print_array(result2, result_len2);
   g_assert(0 == memcmp(expected_result2, result2, result_len2));
   fp_dbg("tls prf test 2 OK");
}

static gboolean serialize_tls_record(record_t *record, guint8 *serialized,
                                     gsize serialized_len)
{
   switch (record->type) {
   case RECORD_TYPE_HANDSHAKE:
      break;

   default:
      fp_err("Unimplemented record type to serialize: %d", record->type);
      goto error;
   }

   return TRUE;
error:
   return FALSE;
}

static gboolean parse_and_store_pairing_privkey(FpiDeviceSynapticsMoc *self,
                                                guint8 *data, gsize data_len)
{
   gboolean ret = TRUE;
   GNUTLS_CHECK(gnutls_privkey_init(&self->pairing_data.private_key));
   // if (0 != gnutls_privkey_import())
   // FIXME: todo

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

static gboolean serialize_certificate_record_data(guint8 *certificate,
                                                  guint8 *serialized,
                                                  gsize *serialized_len)
{
   return TRUE;
}

static gboolean get_remote_tls_status(FpiDeviceSynapticsMoc *self,
                                      gboolean *status, GError *error)
{
   FpiUsbTransfer *transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   // bmRequestType = 0xC0
   // bRequest = 0x14
   // wValue =0
   // wIndex = 0
   // data_or_wLength = 2
   // timeout = 2000

   fpi_usb_transfer_fill_control(
       transfer, G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
       /*these are pure educated guesses*/
       // if does now work try vendor type
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

   return TRUE;
error:
   g_error("Error in function %s: %d aka '%s'", __FUNCTION__, error->code,
           error->message);
   return FALSE;
}

static void update_handshake_messages_data(FpiDeviceSynapticsMoc *self,
                                           const guint8 *data, const gsize size)
{
   // FIXME: do not update with finished messages
   gsize remaining_alloc_size =
       self->tls.sent_data_alloc_size - self->tls.sent_data_size;

   if (remaining_alloc_size <= size) {
      gsize realloc_size = (self->tls.sent_data_alloc_size + size) * 2;
      self->tls.sent_data = g_realloc(self->tls.sent_data, realloc_size);
      self->tls.sent_data_alloc_size = realloc_size;
   }

   memcpy(&self->tls.sent_data[self->tls.sent_data_size], data, size);
   self->tls.sent_data_size += size;

   // TODO: debug start
   fp_dbg("sent messages:");
   print_array(self->tls.sent_data, self->tls.sent_data_size);
   // TODO: debug end
}

static void update_handshake_messages_data_record(FpiDeviceSynapticsMoc *self,
                                                  const record_t *rec)
{
   update_handshake_messages_data(self, rec->msg, rec->msg_len);
}

static gboolean send_tls(FpiDeviceSynapticsMoc *self,
                         const record_t *send_records,
                         const guint send_record_cnt, guint8 **recv_data,
                         gsize *recv_size, GError *error)
{
   gboolean ret = TRUE;
   /* +3 is the padding? */
   *recv_size = 256;

   guint8 *send_data = NULL;

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init(&writer);
   /* write command ID */
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_TLS_DATA);
   /* some padding? */
   written &= fpi_byte_writer_put_uint8(&writer, 0);
   written &= fpi_byte_writer_put_uint8(&writer, 0);
   written &= fpi_byte_writer_put_uint8(&writer, 0);

   for (int i = 0; i < send_record_cnt; ++i) {
      /* write record header */
      written &= fpi_byte_writer_put_uint8(&writer, send_records[i].type);
      written &=
          fpi_byte_writer_put_uint8(&writer, send_records[i].version_major);
      written &=
          fpi_byte_writer_put_uint8(&writer, send_records[i].version_minor);
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
      g_free(recv_data);
   }
   return ret;
}

static gboolean init_client_hello(FpiDeviceSynapticsMoc *self,
                                  hello_t *client_hello)
{
   GDateTime *datetime = g_date_time_new_now_utc();

   client_hello->version_major = self->tls.version_major,
   client_hello->version_minor = self->tls.version_minor;
   client_hello->current_timestamp = g_date_time_to_unix(datetime);

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

   fp_dbg("Client random is:");
   guint8 serialized_timestamp[sizeof(client_hello->current_timestamp)];
   FP_WRITE_UINT32_BE(serialized_timestamp, client_hello->current_timestamp);
   fp_dbg("\ttimestamp:");
   print_array(serialized_timestamp, sizeof(client_hello->current_timestamp));
   fp_dbg("\trand:");
   print_array(client_hello->random, sizeof(client_hello->random));

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
error:
   if (client_hello->extensions != NULL) {
      g_free(client_hello->extensions);
   }
   return FALSE;
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
   const guint8 *recv_random;
   read_ok &= fpi_byte_reader_get_data(reader, sizeof(self->tls.server_random),
                                       &recv_random);
   if (read_ok) {
      memcpy(&self->tls.server_random, recv_random,
             sizeof(self->tls.server_random));
   }
   fp_dbg("received server_random:");
   print_array(recv_random, sizeof(self->tls.server_random));

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
         if (self->tls.handshake_state != TLS_HANDSHAKE_START) {
            fp_err("Unexpected recieval of handshake finished message");
            ret = FALSE;
         }
         // FIXME: check sent messages hash
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

   record_t record = {.msg_len = 0};
   while ((fpi_byte_reader_get_remaining(&reader) != 0) && read_ok) {
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
         read_ok &= parse_and_process_handshake_record(self, &record);
         break;
      case RECORD_TYPE_ALERT:;
         guint8 alert_level = record.msg[0];
         guint8 alert_description = record.msg[1];
         if (read_ok) {
            log_tls_alert_msg(alert_level, alert_description);
         }
         self->tls.handshake_state = TLS_HANDSHAKE_ALERT;
         goto error;

         break;
      default:
         fp_err("Got unimplemented record type: %d", record.type);
         goto error;
      }
   }

error:
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

   // TODO: abstract into kex if not used elsewhere
   // the flag GNUTLS_KEY_DIGITAL_SIGNATURE is a guess
   GNUTLS_CHECK(gnutls_pubkey_import_privkey(pubkey, *privkey,
                                             GNUTLS_KEY_DIGITAL_SIGNATURE, 0));

   gnutls_datum_t x;
   gnutls_datum_t y;
   GNUTLS_CHECK(gnutls_pubkey_export_ecc_raw(pubkey, NULL, &x, &y));
   gnutls_pubkey_deinit(pubkey);

   // TODO: debug start
   fp_dbg("exported pubkey");
   fp_dbg("\tx");
   print_array(x.data, x.size);
   fp_dbg("\ty");
   print_array(y.data, y.size);
   // TODO: debug end

   /* uncompressed format */
   guint x_offset = x.size - 32;
   guint y_offset = y.size - 32;

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

   // TODO: debug start
   fp_dbg("Messages to certificate veify");
   print_array(self->tls.sent_data, self->tls.sent_data_size);
   // TODO: debug end

   GNUTLS_CHECK(gnutls_hash_fast(GNUTLS_DIG_SHA256, self->tls.sent_data,
                                 self->tls.sent_data_size,
                                 &sent_messages_sha256));

   // TODO: debug start
   fp_dbg("Siging hash:");
   print_array(sent_messages_sha256, sha256_size);
   // TODO: debug end

   // GNUTLS_CHECK(gnutls_privkey_sign_data2(
   GNUTLS_CHECK(gnutls_privkey_sign_hash2(
       self->pairing_data.private_key, GNUTLS_SIGN_ECDSA_SHA256, 0,
       &sent_messages_sha256_datum, &signature));

   // TODO: debug start
   fp_dbg("Signature:");
   print_array(signature.data, signature.size);
   // TODO: debug end

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
   printf("Encrypting record msg:\n");
   print_array(record_to_encrypt->msg, record_to_encrypt->msg_len);

   gboolean ret = TRUE;
   gboolean crypt_initialized = FALSE;

   // Setup storage for additional data
   gsize additional_data_size =
       sizeof(self->tls.encrypt_seq_num) + RECORD_HEADER_SIZE;
   guint8 additional_data[additional_data_size];

   // create random nonce
   guint64 nonce;
   GNUTLS_CHECK(gnutls_rnd(GNUTLS_RND_NONCE, &nonce, sizeof(nonce)));

   // create GCM IV = encryption_iv + nonce
   gnutls_datum_t gcm_iv;
   g_assert(self->tls.encryption_iv.size != 0);
   gcm_iv.size = sizeof(nonce) + self->tls.encryption_iv.size;
   gcm_iv.data = g_malloc(gcm_iv.size * sizeof(*gcm_iv.data));
   memcpy(gcm_iv.data, self->tls.encryption_iv.data,
          self->tls.encryption_iv.size);
   FP_WRITE_UINT64_BE(gcm_iv.data + self->tls.encryption_iv.size, nonce);

   // // TODO: debug start
   // fp_dbg("\nEncryption nonce: %lu", nonce);
   // fp_dbg("\nEncryption IV:");
   // print_array(self->tls.encryption_iv.data, self->tls.encryption_iv.size);
   // fp_dbg("GCM IV:");
   // print_array(gcm_iv.data, gcm_iv.size);
   // fp_dbg("Enctyption key:");
   // print_array(self->tls.encryption_key.data, self->tls.encryption_key.size);
   // // TODO: debug end

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
   written &= fpi_byte_writer_put_uint8(&writer, record_to_encrypt->type);
   written &=
       fpi_byte_writer_put_uint8(&writer, record_to_encrypt->version_major);
   written &=
       fpi_byte_writer_put_uint8(&writer, record_to_encrypt->version_minor);
   written &=
       fpi_byte_writer_put_uint16_be(&writer, record_to_encrypt->msg_len);
   g_assert(written); // NOTE: this should have no way of failing

   // // TODO: debug start
   // fp_dbg("Encryption - auth data:");
   // print_array(additional_data, additional_data_size);
   // // TODO: debug end

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

   printf("Encrypted:\n");
   print_array(*ctext, *ctext_len);

error:
   if (crypt_initialized) {
      gnutls_aead_cipher_deinit(aead_hd);
   }
   if (!ret && *ctext != NULL) {
      g_free(*ctext);
      *ctext = NULL;
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
   guint8 *tls_prf_output = NULL;
   guint8 *to_encrypt = NULL;
   gsize to_encrypt_size = 0;
   guint8 *encrypted = NULL;
   gsize encrypted_size = 0;
   const gsize header_size = 4;

   // TODO: debug start
   fp_dbg("Handshake finished sent messages:");
   print_array(self->tls.sent_data, self->tls.sent_data_size);
   // TODO: debug end

   GNUTLS_CHECK(gnutls_hash_fast(GNUTLS_DIG_SHA256, self->tls.sent_data,
                                 self->tls.sent_data_size,
                                 sent_messages_sha256));
   // TODO: debug start
   fp_dbg("Handshake finished sent messages hash:");
   print_array(sent_messages_sha256, sizeof(sent_messages_sha256));
   // TODO: debug end

   BOOL_CHECK(tls_prf(self->tls.master_secret, "client finished",
                      sent_messages_sha256, sha256_size, &tls_prf_output,
                      prf_size));

   fp_dbg("tls prf client finished output:");
   print_array(tls_prf_output, prf_size);

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
   if (tls_prf_output != NULL) {
      g_free(tls_prf_output);
   }
   if (to_encrypt != NULL) {
      g_free(to_encrypt);
   }
   if (encrypted != NULL) {
      g_free(encrypted);
   }
   return ret;
}

static gboolean generate_and_store_aead_keys(FpiDeviceSynapticsMoc *self)
{
   gboolean ret = TRUE;
   guint8 *data = NULL;

   gsize key_size = self->tls.encryption_key.size;
   if (!tls_prf(self->tls.master_secret, "key expansion",
                self->tls.derive_input, sizeof(self->tls.derive_input), &data,
                4 * key_size)) {
      ret = FALSE;
      goto error;
   }
   // printf("key expansion data:\n");
   // print_array(data, 4 * key_size);

   g_assert(self->tls.encryption_key.size != 0);
   g_assert(self->tls.decryption_key.size != 0);
   g_assert(self->tls.encryption_iv.size != 0);
   g_assert(self->tls.decryption_iv.size != 0);

   // FIXME: g_free in close
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
   if (data != NULL) {
      g_free(data);
   }
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

// gboolean tls_wrap(FpiDeviceSynapticsMoc *self, guint8 *ptext, gsize
// ptext_size,
//                   guint8 **ctext, gsize *ctext_size)
// {
//    gboolean ret = TRUE;
//    guint8 *encrypted_msg = NULL;
//    gsize encrypted_msg_size = 0;
//
//    if (!self->tls.established) {
//       g_warning("Calling wrap while tls is not established");
//       *ctext = ptext;
//       *ctext_size = ptext_size;
//       return ret;
//    }
//
//    BOOL_CHECK(
//        encrypt(self, ptext, ptext_size, &encrypted_msg,
//        &encrypted_msg_size));
//
//    record_t record_to_send = {.type = RECORD_TYPE_APPLICATION_DATA,
//                               .version_major = self->tls.version_major,
//                               .version_minor = self->tls.version_minor,
//                               .msg = encrypted_msg,
//                               .msg_len = encrypted_msg_size};
//
//    BOOL_CHECK(serialize_record(&record_to_send, ctext, ctext_size));
//
// error:
//    if (encrypted_msg != NULL) {
//       g_free(encrypted_msg);
//    }
//    return ret;
// }

gboolean tls_close_sesion(FpiDeviceSynapticsMoc *self, GError *error)
{
   gboolean ret = TRUE;
   record_t record_to_send = {
       .type = RECORD_TYPE_ALERT,
       .version_major = self->tls.version_major,
       .version_minor = self->tls.version_minor,
       .msg_len = 2,
   };

   guint8 msg[record_to_send.msg_len];
   msg[0] = TLS_ALERT_LVL_WARNING;
   msg[1] = TLS_ALERT_DESC_CLOSE_NOTIFY;
   record_to_send.msg = msg;

   guint8 *recv_data;
   gsize recv_data_size;
   BOOL_CHECK(
       send_tls(self, &record_to_send, 1, &recv_data, &recv_data_size, error));

   BOOL_CHECK(parse_and_process_records(self, recv_data, recv_data_size));

   if (recv_data != NULL) {
      g_free(recv_data);
   }

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

   self->tls.handshake_state += 1; // TLS_HANDSHAKE_START

error:
   return ret;
}

static gboolean tls_handshake_state_start(FpiDeviceSynapticsMoc *self,
                                          GError *error)
{
   gboolean ret = TRUE;
   guint8 *recv_data = NULL;

   hello_t client_hello = {.extensions = NULL};
   BOOL_CHECK(init_client_hello(self, &client_hello));

   record_t client_hello_record;
   BOOL_CHECK(
       get_client_hello_record(self, &client_hello, &client_hello_record));

   /* update stored all sent msg data */
   update_handshake_messages_data_record(self, &client_hello_record);

   gsize recv_data_size;

   BOOL_CHECK(send_tls(self, &client_hello_record, 1, &recv_data,
                       &recv_data_size, error));

   if (!parse_and_process_records(self, recv_data, recv_data_size)) {
      goto error;
   }

   self->tls.handshake_state = TLS_HANDSHAKE_END;

   return ret;
error:
   if (client_hello.extensions != NULL) {
      g_free(client_hello.extensions);
   }
   if (recv_data != NULL) {
      g_free(recv_data);
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

   gnutls_datum_t premaster_secret;
   BOOL_CHECK(calculate_premaster_secret(self, privkey, &premaster_secret));

   // TODO: debug start
   fp_dbg("premaster_secret:");
   print_array(premaster_secret.data, premaster_secret.size);
   // TODO: debug end

   /* prepare derive_input */
   memcpy(self->tls.derive_input, self->tls.client_random,
          sizeof(self->tls.client_random));
   memcpy(self->tls.derive_input + sizeof(self->tls.client_random),
          self->tls.server_random, sizeof(self->tls.server_random));

   /* calculate master secret */
   self->tls.master_secret.size = MASTER_SECRET_SIZE;
   fp_dbg("calculating master secret form:");
   fp_dbg("\tpremaster secret:");
   print_array(premaster_secret.data, premaster_secret.size);
   fp_dbg("\tseed:");
   print_array(self->tls.derive_input, sizeof(self->tls.derive_input));

   ret &= tls_prf(premaster_secret, "master secret", self->tls.derive_input,
                  sizeof(self->tls.derive_input), &self->tls.master_secret.data,
                  self->tls.master_secret.size);
   //
   // TODO: debug start
   fp_dbg("master_secret:");
   print_array(self->tls.master_secret.data, self->tls.master_secret.size);
   // TODO: debug end

error:
   return ret;
}

static gboolean tls_handshake_state_end(FpiDeviceSynapticsMoc *self,
                                        GError *error)
{
   gboolean ret = TRUE;

   guint8 *recv_data = NULL;

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
   GNUTLS_CHECK(gnutls_privkey_generate(
       privkey, GNUTLS_PK_ECDSA,
       GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0));

   // TODO: DEBUG start
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
   // TODO: DEBUG end

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
       send_tls(self, records_to_send, 3, &recv_data, &recv_size, error));

   BOOL_CHECK(parse_and_process_records(self, recv_data, recv_size));

   self->tls.handshake_state = TLS_HANDSHAKE_FINISHED;

error:
   if (recv_data != NULL) {
      g_free(recv_data);
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
         break;

      case TLS_HANDSHAKE_ALERT:
         self->tls.handshake_state += 1; // TLS_HANDSHAKE_FAILED
         break;

      case TLS_HANDSHAKE_FAILED:
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
