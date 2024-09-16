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
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>

#include "fp-device.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_KDF, EVP_KDF_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_KDF_CTX, EVP_KDF_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_MD_CTX, EVP_MD_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_PARAM_BLD, OSSL_PARAM_BLD_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_PARAM, OSSL_PARAM_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_DECODER_CTX, OSSL_DECODER_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIGNUM, BN_free);

#define RETURN_FALSE_AND_SET_ERROR_IF_NOT_WRITTEN(written)                   \
  do {                                                                       \
    if (!(written))                                                          \
    {                                                                        \
      FP_ERR_WITH_LOCATION("fpi_byte_writer writing error");                 \
      g_propagate_error(                                                     \
          error, fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,           \
                                          "fpi_byte_writer writing error")); \
      return FALSE;                                                          \
    }                                                                        \
  } while (0)

#define RETURN_FALSE_AND_SET_ERROR_IF_NOT_READ(read_ok)                      \
  do {                                                                       \
    if (!(read_ok))                                                          \
    {                                                                        \
      FP_ERR_WITH_LOCATION("fpi_byte_reader reading error");                 \
      g_propagate_error(                                                     \
          error, fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,           \
                                          "fpi_byte_reader reading error")); \
      return FALSE;                                                          \
    }                                                                        \
  } while (0)

#define FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written)              \
  do {                                                                \
    if (!(written))                                                   \
    {                                                                 \
      FP_ERR_WITH_LOCATION("fpi_byte_writer writing error");          \
      fpi_ssm_mark_failed(                                            \
          self->task_ssm,                                             \
          fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,           \
                                   "fpi_byte_writer writing error")); \
      return;                                                         \
    }                                                                 \
  } while (0)

#define FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size)    \
  do {                                                                    \
    if (fpi_byte_writer_get_pos(&writer) != send_size)                    \
    {                                                                     \
      FP_ERR_WITH_LOCATION(                                               \
          "fpi_byte_writer invalid position - got: %d, expected: %d",     \
          fpi_byte_writer_get_pos(&writer), send_size);                   \
      fpi_ssm_mark_failed(                                                \
          self->task_ssm,                                                 \
          fpi_device_error_new_msg(                                       \
              FP_DEVICE_ERROR_GENERAL,                                    \
              "fpi_byte_writer invalid position - got: %d, expected: %d", \
              fpi_byte_writer_get_pos(&writer), send_size));              \
      return;                                                             \
    }                                                                     \
  } while (0)

#define FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok)                 \
  do {                                                                \
    if (!(read_ok))                                                   \
    {                                                                 \
      FP_ERR_WITH_LOCATION("fpi_byte_reader reading error");          \
      fpi_ssm_mark_failed(                                            \
          self->task_ssm,                                             \
          fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,           \
                                   "fpi_byte_reader reading error")); \
      return;                                                         \
    }                                                                 \
  } while (0)

#define FP_ERR_WITH_LOCATION(msg, ...) \
  fp_err("%s: %s: %d:" msg, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define FP_DBG_HIGHLIGHTED(msg, ...)                     \
  fp_dbg("======================================== " msg \
         " ========================================",    \
         ##__VA_ARGS__)

gchar *bin2hex(const guint8 *arr, const gsize size);
const char *status_to_str(guint16 status);
const char *cmd_to_str(guint8 cmd);
const char *event_type_to_str(guint8 event_type);
const char *obj_type_to_str(guint8 obj_type);
void reverse_array(guint8 *arr, gsize size);
GError *set_and_report_error(FpDeviceError device_error, const gchar *msg, ...)
    G_GNUC_PRINTF(2, 3);
