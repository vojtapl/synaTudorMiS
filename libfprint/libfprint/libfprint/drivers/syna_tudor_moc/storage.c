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
#include "container.c"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "tls.h"
#include "utils.h"
#include <gnutls/abstract.h>

static gboolean serialize_private_key(FpiDeviceSynaTudorMoc *self,
                                      FpiByteWriter *writer, GError **error)
{
   gboolean ret = TRUE;

   if (!self->pairing_data.private_key_initialized) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Unable to save a private_key which is not initialized");
      ret = FALSE;
      goto error;
   }
   gnutls_datum_t x;
   gnutls_datum_t y;
   gnutls_datum_t k;
   /* as we use only one curve, there is no need to store it */
   GNUTLS_CHECK(gnutls_privkey_export_ecc_raw2(self->pairing_data.private_key,
                                               NULL, &x, &y, &k,
                                               GNUTLS_EXPORT_FLAG_NO_LZ));

   guint32 total_size = 3 * sizeof(guint32) + x.size + y.size + k.size;
   ret &= fpi_byte_writer_put_uint32_le(writer, total_size);

   ret &= fpi_byte_writer_put_uint32_le(writer, x.size);
   ret &= fpi_byte_writer_put_data(writer, x.data, x.size);

   ret &= fpi_byte_writer_put_uint32_le(writer, y.size);
   ret &= fpi_byte_writer_put_data(writer, y.data, y.size);

   ret &= fpi_byte_writer_put_uint32_le(writer, k.size);
   ret &= fpi_byte_writer_put_data(writer, k.data, k.size);

error:
   return ret;
}

/* Serialize pairing data as a container */
static gboolean serialize_pairing_data(FpiDeviceSynaTudorMoc *self,
                                       guint8 **serialized_data,
                                       gsize *serialized_size, GError **error)
{
   gboolean ret = TRUE;

   FpiByteWriter writer;
   fpi_byte_writer_init(&writer);

   gboolean written = TRUE;

   /* write version tag */
   written &= fpi_byte_writer_put_uint16_le(&writer, PAIR_DATA_TAG_VERSION);
   written &= fpi_byte_writer_put_uint32_le(&writer, sizeof(pair_data_version));
   written &= fpi_byte_writer_put_uint16_le(&writer, pair_data_version);

   /* write host certificate tag */
   written &= fpi_byte_writer_put_uint16_le(&writer, PAIR_DATA_TAG_HOST_CERT);
   written &= fpi_byte_writer_put_uint32_le(&writer, CERTIFICATE_SIZE);
   written &= fpi_byte_writer_put_data(
       &writer, (guint8 *)&self->pairing_data.host_cert, CERTIFICATE_SIZE);

   /* write private key tag */
   written &= fpi_byte_writer_put_uint16_le(&writer, PAIR_DATA_TAG_PRIVATE_KEY);
   written &= serialize_private_key(self, &writer, error);

   /* write sensor certificate tag */
   written &= fpi_byte_writer_put_uint16_le(&writer, PAIR_DATA_TAG_SENSOR_CERT);
   written &= fpi_byte_writer_put_uint32_le(&writer, CERTIFICATE_SIZE);
   written &= fpi_byte_writer_put_data(
       &writer, (guint8 *)&self->pairing_data.sensor_cert, CERTIFICATE_SIZE);

   WRITTEN_CHECK(written);

   *serialized_size = fpi_byte_writer_get_pos(&writer);
   *serialized_data = fpi_byte_writer_reset_and_get_data(&writer);
   g_assert(*serialized_data != NULL);

#ifdef STORAGE_DEBUG
   fp_dbg("Serialized pairing data data:");
   fp_dbg_large_hex(*serialized_data, *serialized_size);
#endif

error:
   return ret;
}

static gboolean host_partition_serialize(FpiDeviceSynaTudorMoc *self,
                                         guint8 **serialized,
                                         gsize *serialized_size, GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *serialized_pairing_data = NULL;
   gsize serialized_pairing_data_size = 0;

   const guint container_cnt = 2;
   hash_container_item_t container[container_cnt];

   guint8 host_data_version_serialized[sizeof(host_data_version)];
   FP_WRITE_UINT32_LE(host_data_version_serialized, host_data_version);

   container[0].cont.id = HOST_DATA_TAG_VERSION;
   container[0].cont.data = host_data_version_serialized;
   container[0].cont.data_size = sizeof(host_data_version);
   BOOL_CHECK(hash_container_add_hash(&container[0], error));

   BOOL_CHECK(serialize_pairing_data(self, &serialized_pairing_data,
                                     &serialized_pairing_data_size, error));

   container[1].cont.id = HOST_DATA_TAG_PAIRED_DATA;
   container[1].cont.data = serialized_pairing_data;
   container[1].cont.data_size = serialized_pairing_data_size;
   BOOL_CHECK(hash_container_add_hash(&container[1], error));

   BOOL_CHECK(serialize_hash_container(container, container_cnt, serialized,
                                       serialized_size));

#ifdef STORAGE_DEBUG
   fp_dbg("Serialized host partition data:");
   fp_dbg_large_hex(*serialized, *serialized_size);
#endif

error:
   return ret;
}

static gboolean check_host_data_version(hash_container_item_t *hash_cont,
                                        GError **error)
{
   gboolean ret = TRUE;

   if (hash_cont->cont.data_size != sizeof(host_data_version)) {
      *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "Invalid host data version tag length: %d",
                                    hash_cont->cont.data_size);
      ret = FALSE;
      goto error;
   }

   guint32 recv_version = FP_READ_UINT32_LE(hash_cont->cont.data);
   if (recv_version != host_data_version) {
      *error =
          set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                               "Invalid host data version: %d", recv_version);
      ret = FALSE;
      goto error;
   }

error:
   return ret;
}

static gboolean check_pairing_data_version(container_item_t *cont,
                                           GError **error)
{
   gboolean ret = TRUE;

   if (cont->data_size != sizeof(pair_data_version)) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL, "Stored pairing data has invalid length: %d",
          cont->data_size);
      ret = FALSE;
      goto error;
   }

   guint16 recv_pair_data_version = FP_READ_UINT16_LE(cont->data);
   if (recv_pair_data_version != pair_data_version) {
      *error =
          set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                               "Stored pairing data has invalid version: %d",
                               recv_pair_data_version);
      ret = FALSE;
      goto error;
   }

error:
   return ret;
}

static gboolean load_host_cert(FpiDeviceSynaTudorMoc *self,
                               container_item_t *cont, GError **error)
{
   gboolean ret = TRUE;

   if (cont->data_size != CERTIFICATE_SIZE) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Stored host certificate has invalid size: %d", cont->data_size);
      ret = FALSE;
      goto error;
   }

   BOOL_CHECK(parse_certificate(cont->data, CERTIFICATE_SIZE,
                                &self->pairing_data.host_cert));

error:
   return ret;
}

static gboolean load_sensor_cert(FpiDeviceSynaTudorMoc *self,
                                 container_item_t *cont, GError **error)
{
   gboolean ret = TRUE;

   if (cont->data_size != CERTIFICATE_SIZE) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Stored sensor certificate has invalid size: %d", cont->data_size);
      ret = FALSE;
      goto error;
   }

   BOOL_CHECK(parse_certificate(cont->data, CERTIFICATE_SIZE,
                                &self->pairing_data.sensor_cert));

error:
   return ret;
}

static gboolean load_privkey(FpiDeviceSynaTudorMoc *self,
                             container_item_t *cont, GError **error)
{
   gboolean ret = TRUE;

   gnutls_datum_t x = {.data = NULL};
   gnutls_datum_t y = {.data = NULL};
   gnutls_datum_t k = {.data = NULL};

   if (self->pairing_data.private_key_initialized) {
      fp_warn("Overwriting stored private key");
   } else {
      gnutls_privkey_init(&self->pairing_data.private_key);
      self->pairing_data.private_key_initialized = TRUE;
   }

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, cont->data, cont->data_size);

   ret &= fpi_byte_reader_get_uint32_le(&reader, &x.size);
   ret &= fpi_byte_reader_dup_data(&reader, x.size, &x.data);

   ret &= fpi_byte_reader_get_uint32_le(&reader, &y.size);
   ret &= fpi_byte_reader_dup_data(&reader, y.size, &y.data);

   ret &= fpi_byte_reader_get_uint32_le(&reader, &k.size);
   ret &= fpi_byte_reader_dup_data(&reader, k.size, &k.data);

   /* as we use only one curve, there is no need to read it */
   GNUTLS_CHECK(gnutls_privkey_import_ecc_raw(
       self->pairing_data.private_key, GNUTLS_ECC_CURVE_SECP256R1, &x, &y, &k));
   GNUTLS_CHECK(gnutls_privkey_verify_params(self->pairing_data.private_key));

error:
   if (x.data != NULL) {
      g_free(x.data);
   }
   if (y.data != NULL) {
      g_free(y.data);
   }
   if (k.data != NULL) {
      g_free(k.data);
   }
   return ret;
}

static gboolean deserialize_pairing_data(FpiDeviceSynaTudorMoc *self,
                                         hash_container_item_t *hash_cont,
                                         GError **error)
{
   gboolean ret = TRUE;

   g_autofree container_item_t *cont = NULL;
   guint cont_cnt = 0;
   BOOL_CHECK(deserialize_container(
       hash_cont->cont.data, hash_cont->cont.data_size, &cont, &cont_cnt));

   guint version_tag_idx = 0;
   guint host_cert_tag_idx = 0;
   guint privkey_tag_idx = 0;
   guint sensor_cert_tag_idx = 0;

   if (self->pairing_data.present) {
      fp_warn("Overwriting currently present pairing_data");
      /* we do not want to accept partial loading of pairing data */
      self->pairing_data.present = FALSE;
   }

   BOOL_CHECK(get_container_with_id_index(cont, cont_cnt, PAIR_DATA_TAG_VERSION,
                                          &version_tag_idx));
   BOOL_CHECK(get_container_with_id_index(
       cont, cont_cnt, PAIR_DATA_TAG_HOST_CERT, &host_cert_tag_idx));
   BOOL_CHECK(get_container_with_id_index(
       cont, cont_cnt, PAIR_DATA_TAG_PRIVATE_KEY, &privkey_tag_idx));
   BOOL_CHECK(get_container_with_id_index(
       cont, cont_cnt, PAIR_DATA_TAG_SENSOR_CERT, &sensor_cert_tag_idx));

   BOOL_CHECK(check_pairing_data_version(&cont[version_tag_idx], error));

   BOOL_CHECK(load_host_cert(self, &cont[host_cert_tag_idx], error));
   BOOL_CHECK(load_privkey(self, &cont[privkey_tag_idx], error));
   BOOL_CHECK(load_sensor_cert(self, &cont[sensor_cert_tag_idx], error));

   self->pairing_data.present = TRUE;

error:
   return ret;
}

static gboolean host_partition_deserialize(FpiDeviceSynaTudorMoc *self,
                                           guint8 *serialized,
                                           gsize serialized_size,
                                           GError **error)
{
   gboolean ret = TRUE;

   hash_container_item_t *hash_cont = NULL;
   guint cont_cnt = 0;

   BOOL_CHECK(deserialize_hash_container(serialized, serialized_size,
                                         &hash_cont, &cont_cnt, error));

   guint host_data_version_idx = 0;
   BOOL_CHECK(get_hash_container_with_id_index(
       hash_cont, cont_cnt, HOST_DATA_TAG_VERSION, &host_data_version_idx));

   guint host_data_pairing_data_idx = 0;
   BOOL_CHECK(get_hash_container_with_id_index(hash_cont, cont_cnt,
                                               HOST_DATA_TAG_PAIRED_DATA,
                                               &host_data_pairing_data_idx));

   BOOL_CHECK(
       check_host_data_version(&hash_cont[host_data_version_idx], error));

   BOOL_CHECK(deserialize_pairing_data(
       self, &hash_cont[host_data_pairing_data_idx], error));

error:
   return ret;
}

gboolean host_partition_store_pairing_data(FpiDeviceSynaTudorMoc *self,
                                           GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *serialized = NULL;
   gsize serialized_size = 0;

   BOOL_CHECK(
       host_partition_serialize(self, &serialized, &serialized_size, error));

   BOOL_CHECK(write_host_partition(self, serialized, serialized_size, error));

error:
   return ret;
}

gboolean host_partition_load_pairing_data(FpiDeviceSynaTudorMoc *self,
                                          GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *serialized = NULL;
   guint32 serialized_size = 0;

   BOOL_CHECK(read_host_partition(self, &serialized, &serialized_size, error));

   BOOL_CHECK(
       host_partition_deserialize(self, serialized, serialized_size, error));

error:
   return ret;
}
