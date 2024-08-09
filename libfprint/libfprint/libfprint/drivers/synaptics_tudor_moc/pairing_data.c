/*
 * TODO: header
 */

#include "fpi-byte-reader.h"
#include "pairing_data.h"

gboolean parse_sensor_certificate(guint8 *to_parse, gsize to_parse_len,
                                  sensor_cert_t *parsed_cert)
{
   g_assert(to_parse_len == SENSOR_CERT_BYTES_LEN);

   FpiByteReader reader;
   gboolean read_ok = TRUE;
   guint offset = 0;

   fpi_byte_reader_init(&reader, to_parse, to_parse_len);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &parsed_cert->magic);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &parsed_cert->curve);

   offset = fpi_byte_reader_get_pos(&reader);
   memcpy(parsed_cert->pub_x, &to_parse[offset], sizeof(parsed_cert->pub_x));
   read_ok &= fpi_byte_reader_skip(&reader, sizeof(parsed_cert->pub_x));

   offset = fpi_byte_reader_get_pos(&reader);
   memcpy(parsed_cert->pub_y, &to_parse[offset], sizeof(parsed_cert->pub_y));
   read_ok &= fpi_byte_reader_skip(&reader, sizeof(parsed_cert->pub_y));

   read_ok &= fpi_byte_reader_get_uint8(&reader, &parsed_cert->cert_type);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &parsed_cert->sign_size);

   offset = fpi_byte_reader_get_pos(&reader);
   memcpy(parsed_cert->sign, &to_parse[offset], sizeof(parsed_cert->sign));

   /*this should have no way of failing*/
   g_assert(read_ok);

   g_assert(parsed_cert->magic == 0x5f3f);
   g_assert(parsed_cert->curve == 23);

   return TRUE;
error:
   return FALSE;
}
