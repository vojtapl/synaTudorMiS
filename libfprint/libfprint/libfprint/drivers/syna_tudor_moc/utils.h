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

#include "fpi-log.h"
#include <glib.h>

#pragma once

#define BOOL_CHECK(func_call)                                                  \
   do {                                                                        \
      gboolean func_ret = (func_call);                                         \
      if (!func_ret) {                                                         \
         fp_err("%s: %s: %d: Error in " #func_call, __FILE__, __FUNCTION__,    \
                __LINE__);                                                     \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)
#define WRITTEN_CHECK(condition)                                               \
   do {                                                                        \
      if (!(condition)) {                                                      \
         fp_err("%s: %s: %d: writing error occured", __FILE__, __FUNCTION__,   \
                __LINE__);                                                     \
         *error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,            \
                                           "fpi_byte_writer writing error");   \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)
#define READ_OK_CHECK(condition)                                               \
   do {                                                                        \
      if (!(condition)) {                                                      \
         fp_err("%s: %s: %d: reading error occured", __FILE__, __FUNCTION__,   \
                __LINE__);                                                     \
         *error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,            \
                                           "fpi_byte_reader reading error");   \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)

void reverse_array(guint8 *arr, gsize size);

void fp_dbg_large_hex(const guint8 *arr, const gint size);
