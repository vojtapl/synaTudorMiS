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

#include "container.h"
#include "device.h"
#include "fpi-byte-writer.h"
#include "fpi-log.h"
#include "utils.c"
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

// #define CONTAINER_DEBUG

/* Container =============================================================== */

static gsize get_serialized_container_size(container_item_t *cont,
                                           guint cont_cnt)
{
   g_return_val_if_fail(cont != NULL, 0);

   gsize size = 0;
   for (int i = 0; i < cont_cnt; ++i) {
      size += cont[i].data_size + CONTAINTER_HEADER_SIZE;
   }

   return size;
}

gboolean serialize_container(container_item_t *cont, guint cont_cnt,
                             guint8 **serialized, gsize *serialized_size)
{
   gboolean read_ok = TRUE;

   *serialized_size = get_serialized_container_size(cont, cont_cnt);
   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, *serialized_size, TRUE);

   for (int i = 0; i < cont_cnt; ++i) {
      read_ok &= fpi_byte_writer_put_uint16_le(&writer, cont[i].id);
      read_ok &= fpi_byte_writer_put_uint32_le(&writer, cont[i].data_size);
      read_ok &=
          fpi_byte_writer_put_data(&writer, cont[i].data, cont[i].data_size);
   }

   *serialized = fpi_byte_writer_reset_and_get_data(&writer);

   if (!read_ok && *serialized != NULL) {
      g_free(*serialized);
      *serialized = NULL;
   }
   return read_ok;
}

gboolean deserialize_container(const guint8 *serialized,
                               const gsize serialized_size,
                               container_item_t **cont, guint *cont_item_cnt)
{
   guint allocated_cont_item_cnt = 5;
   *cont_item_cnt = 0;

   *cont = g_new(container_item_t, allocated_cont_item_cnt);

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, serialized, serialized_size);
   while (read_ok &&
          fpi_byte_reader_get_remaining(&reader) >= CONTAINTER_HEADER_SIZE) {
#ifdef CONTAINER_DEBUG
      fp_dbg("Container index: %d", *cont_item_cnt);
#endif

      read_ok &=
          fpi_byte_reader_get_uint16_le(&reader, &(*cont)[*cont_item_cnt].id);
      fp_dbg("\tid: %u", (*cont)[*cont_item_cnt].id);
      read_ok &= fpi_byte_reader_get_uint32_le(
          &reader, &(*cont)[*cont_item_cnt].data_size);
      fp_dbg("\tsize: %u", (*cont)[*cont_item_cnt].data_size);
      read_ok &=
          fpi_byte_reader_dup_data(&reader, (*cont)[*cont_item_cnt].data_size,
                                   &((*cont)[*cont_item_cnt].data));
      if (read_ok) {
#ifdef CONTAINER_DEBUG
         fp_dbg("\tid: %u", (*cont)[*cont_item_cnt].id);
         fp_dbg("\tsize: %u", (*cont)[*cont_item_cnt].data_size);
         fp_dbg("\tdata:");
         fp_dbg_large_hex((*cont)[*cont_item_cnt].data,
                          (*cont)[*cont_item_cnt].data_size);
#endif
         *cont_item_cnt += 1;

         if (*cont_item_cnt >= allocated_cont_item_cnt) {
            allocated_cont_item_cnt *= 2;
            *cont = g_realloc_n(*cont, allocated_cont_item_cnt,
                                sizeof(container_item_t));
         }
      }
   }

   if (!read_ok && *cont != NULL) {
      /* free container data */
      for (int i = 0; i < *cont_item_cnt; ++i) {
         if ((*cont)[i].data != NULL) {

            g_free((*cont)[i].data);
         }
      }
      g_free(*cont);
      *cont = NULL;
   }
   return read_ok;
}

gboolean get_container_with_id_index(container_item_t *container,
                                     guint container_cnt, guint8 id, guint *idx)
{
   for (int i = 0; i < container_cnt; ++i) {
      if (container[i].id == id) {
         *idx = i;
         return TRUE;
      }
   }

   return FALSE;
}

gboolean get_enrollment_data_from_serialized_container(const guint8 *data,
                                                       const gsize data_size,
                                                       enrollment_t *enrollment,
                                                       GError **error)
{
   gboolean ret = TRUE;

   guint container_array_len = 0;
   g_autofree container_item_t *container_array;
   BOOL_CHECK(deserialize_container(data, data_size, &container_array,
                                    &container_array_len));

   guint template_id_idx;
   BOOL_CHECK(get_container_with_id_index(container_array, container_array_len,
                                          ENROLL_TAG_TEMPLATE_ID,
                                          &template_id_idx));

   guint user_id_idx;
   BOOL_CHECK(get_container_with_id_index(container_array, container_array_len,
                                          ENROLL_TAG_USER_ID, &user_id_idx));

   guint finger_id_idx;
   BOOL_CHECK(get_container_with_id_index(container_array, container_array_len,
                                          ENROLL_TAG_FINGER_ID,
                                          &finger_id_idx));

   if (container_array[template_id_idx].data_size != DB2_ID_SIZE) {
      fp_err("Container item at id: %d has invalid size: %d for template_id, "
             "which requires: %lu",
             template_id_idx, container_array[template_id_idx].data_size,
             sizeof(template_id_idx));
      *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "container item has invalid size");

      ret = FALSE;
      goto error;
   }
   memcpy(enrollment->template_id, container_array[template_id_idx].data,
          DB2_ID_SIZE);

   if (container_array[user_id_idx].data_size != sizeof(user_id_t)) {
      fp_err("Container item at id: %d has invalid size: %d for user_id, which "
             "requires: %lu",
             user_id_idx, container_array[user_id_idx].data_size,
             sizeof(user_id_idx));
      *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "container item has invalid size");
      ret = FALSE;
      goto error;
   }
   memcpy(enrollment->user_id, container_array[user_id_idx].data,
          sizeof(user_id_t));

   if (container_array[finger_id_idx].data_size != sizeof(guint8)) {
      fp_err(
          "Container item at id: %d has invalid size: %d for finger_id, which "
          "requires: %lu",
          finger_id_idx, container_array[finger_id_idx].data_size,
          sizeof(guint8));
      *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "container item has invalid size");
      ret = FALSE;
      goto error;
   }
   /* finger id is guint8, so no need to memcpy */
   enrollment->finger_id = container_array[finger_id_idx].data[0];

error:
   for (int i = 0; i < container_array_len; ++i) {
      g_free(container_array[i].data);
   }
   return ret;
}

/* Hash Container ========================================================== */

static gsize
get_serialized_hash_container_size(hash_container_item_t *hash_cont,
                                   guint cont_cnt)
{
   g_return_val_if_fail(hash_cont != NULL, 0);

   gsize size = 0;
   for (int i = 0; i < cont_cnt; ++i) {
      size +=
          hash_cont[i].cont.data_size + CONTAINTER_HEADER_SIZE + SHA256_SIZE;
   }

   return size;
}

static gboolean get_container_hash(container_item_t *cont,
                                   guint8 sha256_hash[SHA256_SIZE],
                                   GError **error)
{
   gboolean ret = TRUE;

   gnutls_hash_hd_t hash_hd;
   GNUTLS_CHECK(gnutls_hash_init(&hash_hd, GNUTLS_DIG_SHA256));
   GNUTLS_CHECK(gnutls_hash(hash_hd, &cont->id, sizeof(cont->id)));
   GNUTLS_CHECK(
       gnutls_hash(hash_hd, &cont->data_size, sizeof(cont->data_size)));
   GNUTLS_CHECK(gnutls_hash(hash_hd, cont->data, cont->data_size));
   gnutls_hash_deinit(hash_hd, sha256_hash);

#ifdef CONTAINER_DEBUG
   fp_dbg("Hashing container:");
   fp_dbg("\tid: %d", cont->id);
   fp_dbg("\tdata_size: %d", cont->data_size);
   fp_dbg("\tdata:");
   fp_dbg_large_hex(cont->data, cont->data_size);
   fp_dbg("calculated container hash:");
   fp_dbg_large_hex(sha256_hash, SHA256_SIZE);
#endif

error:
   return ret;
}

gboolean hash_container_add_hash(hash_container_item_t *hash_cont,
                                 GError **error)
{
   gboolean ret = TRUE;

   BOOL_CHECK(
       get_container_hash(&hash_cont->cont, hash_cont->sha256_hash, error));

error:
   return ret;
}

gboolean hash_container_check_hashes(hash_container_item_t *hash_cont,
                                     guint cont_item_cnt, GError **error)
{
   gboolean ret = TRUE;
   guint8 calculated_hash[SHA256_SIZE];

   for (int i = 0; i < cont_item_cnt; ++i) {
      BOOL_CHECK(
          get_container_hash(&hash_cont[i].cont, calculated_hash, error));

#ifdef CONTAINER_DEBUG
      fp_dbg("expected container hash:");
      fp_dbg_large_hex(hash_cont[i].sha256_hash, 32);
#endif

      if (0 != memcmp(calculated_hash, hash_cont[i].sha256_hash, SHA256_SIZE)) {
         *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                       "Container hashes do not match");
         ret = FALSE;
         goto error;
      }
   }

error:
   return ret;
}

gboolean serialize_hash_container(hash_container_item_t *hash_cont,
                                  guint cont_cnt, guint8 **serialized,
                                  gsize *serialized_size)
{
   *serialized_size = get_serialized_hash_container_size(hash_cont, cont_cnt);

   gboolean read_ok = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, *serialized_size, TRUE);
   for (int i = 0; i < cont_cnt; ++i) {
      read_ok &= fpi_byte_writer_put_uint16_le(&writer, hash_cont[i].cont.id);
      read_ok &=
          fpi_byte_writer_put_uint32_le(&writer, hash_cont[i].cont.data_size);
      read_ok &= fpi_byte_writer_put_data(&writer, hash_cont[i].cont.data,
                                          hash_cont[i].cont.data_size);
      read_ok &= fpi_byte_writer_put_data(&writer, hash_cont[i].sha256_hash,
                                          SHA256_SIZE);
   }

   *serialized = fpi_byte_writer_reset_and_get_data(&writer);

   if (!read_ok && *serialized != NULL) {
      g_free(*serialized);
      *serialized = NULL;
   }
   return read_ok;
}

gboolean deserialize_hash_container(const guint8 *serialized,
                                    const gsize serialized_size,
                                    hash_container_item_t **hash_cont,
                                    guint *cont_item_cnt, GError **error)
{
   gboolean ret = TRUE;

   guint allocated_cont_item_cnt = 5;
   *cont_item_cnt = 0;

   *hash_cont = g_new(hash_container_item_t, allocated_cont_item_cnt);

   const guint8 *to_copy = NULL;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, serialized, serialized_size);

   while (ret && fpi_byte_reader_get_remaining(&reader) >=
                     HASH_CONTAINTER_HEADER_SIZE) {
#ifdef CONTAINER_DEBUG
      fp_dbg("Hash container index: %d", *cont_item_cnt);
#endif

      (*hash_cont)[*cont_item_cnt].cont.data = NULL;

      ret &= fpi_byte_reader_get_uint16_le(
          &reader, &(*hash_cont)[*cont_item_cnt].cont.id);
      ret &= fpi_byte_reader_get_uint32_le(
          &reader, &(*hash_cont)[*cont_item_cnt].cont.data_size);
      /* FIXME: find a better way */
      if ((*hash_cont)[*cont_item_cnt].cont.data_size == 0 ||
          (*hash_cont)[*cont_item_cnt].cont.data_size > 0x1000) {
         fp_dbg("\tlast container index has empty data, stopping");
         break;
      }
      ret &= fpi_byte_reader_dup_data(
          &reader, (*hash_cont)[*cont_item_cnt].cont.data_size,
          &((*hash_cont)[*cont_item_cnt].cont.data));
      ret &= fpi_byte_reader_get_data(&reader, SHA256_SIZE, &to_copy);

      if (ret) {
         memcpy(&(*hash_cont)[*cont_item_cnt].sha256_hash, to_copy,
                SHA256_SIZE);
#ifdef CONTAINER_DEBUG
         fp_dbg("\tid: %u", (*hash_cont)[*cont_item_cnt].cont.id);
         fp_dbg("\tsize: %u", (*hash_cont)[*cont_item_cnt].cont.data_size);
         fp_dbg("\tdata:");
         fp_dbg_large_hex((*hash_cont)[*cont_item_cnt].cont.data,
                          (*hash_cont)[*cont_item_cnt].cont.data_size);
         fp_dbg("\thash:");
         fp_dbg_large_hex((*hash_cont)[*cont_item_cnt].sha256_hash,
                          SHA256_SIZE);
#endif
         *cont_item_cnt += 1;

         if (*cont_item_cnt >= allocated_cont_item_cnt) {
            allocated_cont_item_cnt *= 2;
            *hash_cont = g_realloc_n(*hash_cont, allocated_cont_item_cnt,
                                     sizeof(container_item_t));
         }
      }
   }

   READ_OK_CHECK(ret);

   BOOL_CHECK(hash_container_check_hashes(*hash_cont, *cont_item_cnt, error));

   if (!ret && *hash_cont != NULL) {
      /* free container data */
      for (int i = 0; i < *cont_item_cnt; ++i) {
         if ((*hash_cont)[i].cont.data != NULL) {
            g_free((*hash_cont)[i].cont.data);
         }
      }
      g_free(*hash_cont);
      *hash_cont = NULL;
   }
error:
   return ret;
}

gboolean get_hash_container_with_id_index(hash_container_item_t *container,
                                          guint container_cnt, guint8 id,
                                          guint *idx)
{
   for (int i = 0; i < container_cnt; ++i) {
      if (container[i].cont.id == id) {
         *idx = i;
         return TRUE;
      }
   }

   return FALSE;
}
