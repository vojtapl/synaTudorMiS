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

#pragma once

#include <glib.h>
#include <openssl/ec.h>

/* Sensor public keys for Sensor certificate verificaiton
 * SECP256R1 keys converted to big-endian (OpenSSL expects big endian) */
typedef struct
{
  guint8 *key_data;
  gsize key_data_size;

  gboolean keyflag;
  guint8 fw_version_major;
  guint8 fw_version_minor;
} sensor_pub_key_t;

/* ========================================================================= */

guint8 sensor_key_v10_1_data[] = {
  POINT_CONVERSION_UNCOMPRESSED,
  // x
  0x33, 0xd6, 0x20, 0x8c, 0xa5, 0xf5, 0xda, 0x82, 0x4b, 0x46, 0xea, 0x1c,
  0xa2, 0x5e, 0x67, 0x32, 0x7e, 0xfc, 0x0c, 0x4c, 0xe9, 0x37, 0xd9, 0xd8,
  0x44, 0x12, 0x0d, 0x6c, 0xc0, 0x8b, 0xfe, 0x5d,
  // y
  0xb9, 0x55, 0xe1, 0x81, 0xfc, 0x4b, 0xf6, 0xc6, 0x2b, 0x91, 0xaf, 0xcd,
  0xf3, 0xb6, 0x1e, 0xc7, 0x18, 0xdc, 0xe7, 0x08, 0x47, 0x42, 0xc4, 0x1f,
  0x57, 0xc1, 0xf0, 0x77, 0x7c, 0x34, 0xa0, 0xfd
};

sensor_pub_key_t pubkey_v10_1 = {
  .key_data = sensor_key_v10_1_data,
  .key_data_size = sizeof (sensor_key_v10_1_data),
  .fw_version_major = 10,
  .fw_version_minor = 1,
  .keyflag = FALSE,
};

/* ========================================================================= */

guint8 sensor_key_v10_1_kf_data[] = {
  POINT_CONVERSION_UNCOMPRESSED,
  // x
  0xcb, 0x65, 0x62, 0x93, 0xb9, 0x70, 0x18, 0x06, 0xae, 0x3b, 0x1a, 0x52,
  0x08, 0xe4, 0x69, 0xf4, 0x65, 0xa6, 0xa5, 0x19, 0x5b, 0xd8, 0xb7, 0xe3,
  0x9f, 0x23, 0x65, 0x06, 0x11, 0xdc, 0xdf, 0xdc,
  // y
  0xa7, 0x00, 0x42, 0x4e, 0xe0, 0x97, 0xb3, 0xc1, 0x59, 0xbe, 0x79, 0x10,
  0x89, 0x50, 0x2f, 0x40, 0xba, 0x57, 0x1e, 0xca, 0x91, 0xb1, 0x06, 0xb4,
  0x88, 0x1f, 0x19, 0x63, 0x7e, 0x44, 0xbf, 0xdc
};

sensor_pub_key_t pubkey_v10_1_kf = {
  .key_data = sensor_key_v10_1_kf_data,
  .key_data_size = sizeof (sensor_key_v10_1_kf_data),
  .fw_version_major = 10,
  .fw_version_minor = 1,
  .keyflag = TRUE,
};
