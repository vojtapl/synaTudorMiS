/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * Copyright (c) 2024 Francesco Circhetta, Vojtěch Pluskal
 *
 * Some parts are based on:
 *    - work of Popax21, see: https://github.com/Popax21/synaTudor/tree/rev
 *    - egismoc libfprint driver by Joshua Grisham, see egismoc.c,
 *       of which portions are from elanmoc libfprint driver (C) 2021 Elan
 *       Microelectronic
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

#include "fp-device.h"
#define FP_COMPONENT "synamoc-TagVal"

#include <glib.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-device.h"
#include "tagval.h"
#include "utils.h"

TagVal *
tagval_new (void)
{
  TagVal *new = g_new0 (TagVal, 1);

  new->vals = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
                                     (GDestroyNotify) g_bytes_unref);

  return new;
}

void
tagval_free (TagVal *self)
{
  g_hash_table_destroy (self->vals);
  g_free (self);
}

gboolean
tagval_add (TagVal *self, guint16 tag, guint8 *val, guint32 val_size)
{
  return g_hash_table_insert (self->vals, GINT_TO_POINTER (tag),
                              g_bytes_new (val, val_size));
}

gboolean
tagval_new_from_bytes (TagVal **container, guint8 *data, gsize length, GError **error)
{
  FpiByteReader reader;
  gboolean read_ok = TRUE;
  g_autoptr (TagVal) new = tagval_new ();

  fpi_byte_reader_init (&reader, data, length);
  while (fpi_byte_reader_get_remaining (&reader) > 0)
    {
      guint16 tag = 0;
      guint32 val_size = 0;
      guint8 *val = NULL;

      read_ok &= fpi_byte_reader_get_uint16_le (&reader, &tag);
      read_ok &= fpi_byte_reader_get_uint32_le (&reader, &val_size);
      read_ok &= fpi_byte_reader_dup_data (&reader, val_size, &val);

      if (!read_ok)
        {
          g_propagate_error (
              error, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                               "Cannot decode TagVal container"));
          return FALSE;
        }

      if (!g_hash_table_insert (new->vals, GINT_TO_POINTER (tag),
                                g_bytes_new_take (val, val_size)))
        {
          g_propagate_error (error,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                       "Tag %d already exists", tag));
          return FALSE;
        }
    }

  *container = g_steal_pointer (&new);
  return TRUE;
}

void
tagval_to_bytes (TagVal *self, guint8 **serialized, gsize *serialized_length)
{
  FpiByteWriter writer;
  gboolean written = TRUE;
  GHashTableIter iter;
  gpointer ptag, pvalue;

  fpi_byte_writer_init (&writer);
  g_hash_table_iter_init (&iter, self->vals);

  while (g_hash_table_iter_next (&iter, &ptag, &pvalue))
    {
      GBytes *bval = (GBytes *) pvalue;
      guint32 val_size = g_bytes_get_size (bval);
      const guint8 *val = g_bytes_get_data (bval, NULL);

      written &= fpi_byte_writer_put_uint16_le (&writer, GPOINTER_TO_UINT (ptag));
      written &= fpi_byte_writer_put_uint32_le (&writer, val_size);
      written &= fpi_byte_writer_put_data (&writer, val, val_size);

      g_assert (written);
    }

  *serialized_length = fpi_byte_writer_get_pos (&writer);
  *serialized = fpi_byte_writer_reset_and_get_data (&writer);
}

gboolean
tagval_get (TagVal *self, guint16 tag, guint8 **val, gsize *val_size, GError **error)
{
  GBytes *val_bytes = g_hash_table_lookup (self->vals, GINT_TO_POINTER (tag));

  if (val_bytes == NULL)
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Tag %d not found", tag));
    }

  *val = (guint8 *) g_bytes_get_data (val_bytes, NULL);
  *val_size = g_bytes_get_size (val_bytes);
  return TRUE;
}

typedef struct
{
  guint8 *val;
  gsize val_size;
  guint8 *hash;
} HashVal;

static HashVal *
hashval_new (guint8 *val, gsize val_size, guint8 *hash)
{
  HashVal *new = g_new0 (HashVal, 1);
  new->val = val;
  new->val_size = val_size;
  new->hash = hash;
  return new;
}

static void
hashval_free (HashVal *hashval)
{
  g_free (hashval->val);
  g_free (hashval->hash);
  g_free (hashval);
}

static HashTagVal *
hashtagval_new (void)
{
  HashTagVal *new = g_new0 (HashTagVal, 1);

  new->hashvals = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
                                         (GDestroyNotify) hashval_free);

  return new;
}

void
hashtagval_free (HashTagVal *self)
{
  g_hash_table_destroy (self->hashvals);
  g_free (self);
}

HashTagVal *
hashtagval_new_from_bytes (guint8 *container, gsize length, GError **error)
{
  GError *local_error = NULL;
  FpiByteReader reader;
  gboolean read_ok = TRUE;
  HashTagVal *new = hashtagval_new ();

  fpi_byte_reader_init (&reader, container, length);
  while (fpi_byte_reader_get_remaining (&reader) > 0)
    {
      guint16 tag, val_size;
      guint8 *val, *hash;

      read_ok &= fpi_byte_reader_get_uint16_le (&reader, &tag);
      read_ok &= fpi_byte_reader_get_uint16_le (&reader, &val_size);

      if (!read_ok)
        {
          local_error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                  "Cannot decode HashTagVal header");
          goto error;
        }

      if (tag == 0xFFFF)
        break;

      read_ok &= fpi_byte_reader_dup_data (&reader, 32, &hash);
      read_ok &= fpi_byte_reader_dup_data (&reader, val_size, &val);

      if (!read_ok)
        {
          local_error = fpi_device_error_new_msg (
              FP_DEVICE_ERROR_PROTO, "Cannot decode HashTagVal content");
          goto error;
        }

      if (!g_hash_table_insert (new->hashvals, GINT_TO_POINTER (tag),
                                hashval_new (val, val_size, hash)))
        {
          local_error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                  "Tag %d already exists", tag);
          goto error;
        }
    }

  return new;

error:
  hashtagval_free (new);
  g_propagate_error (error, local_error);
  return NULL;
}

gboolean
hashtagval_check_hashes (HashTagVal *self, GError **error)
{
  GHashTableIter iter;
  gpointer ptag, pvalue;
  HashVal *hashval;
  guint8 computed_hash[EVP_MD_get_size (EVP_sha256 ())];
  g_autoptr (EVP_MD_CTX) mdctx = EVP_MD_CTX_new ();

  g_hash_table_iter_init (&iter, self->hashvals);
  while (g_hash_table_iter_next (&iter, &ptag, &pvalue))
    {
      hashval = (HashVal *) pvalue;

      if (!EVP_DigestInit_ex (mdctx, EVP_sha256 (), NULL) ||
          !EVP_DigestUpdate (mdctx, hashval->val, hashval->val_size) ||
          !EVP_DigestFinal_ex (mdctx, computed_hash, NULL))
        {
          g_propagate_error (error, fpi_device_error_new_msg (
                                        FP_DEVICE_ERROR_GENERAL,
                                        "Error while hashing HashTagVal entry: %s",
                                        ERR_error_string (ERR_get_error (), NULL)));
          return FALSE;
        }

      if (memcmp (hashval->hash, computed_hash, 32) != 0)
        {
          g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Tag don't match"));
          return FALSE;
        }
    }
  return TRUE;
}

gboolean
hashtagval_get (HashTagVal *self, guint16 tag, guint8 **val, gsize *val_size, GError **error)
{
  HashVal *hashval = g_hash_table_lookup (self->hashvals, GINT_TO_POINTER (tag));

  if (hashval == NULL)
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Tag %d not found", tag));
      return FALSE;
    }

  *val = hashval->val;
  *val_size = hashval->val_size;
  return TRUE;
}
