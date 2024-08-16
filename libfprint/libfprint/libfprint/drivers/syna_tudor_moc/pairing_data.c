/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * Copyright (c) 2024 Vojtěch Pluskal
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
