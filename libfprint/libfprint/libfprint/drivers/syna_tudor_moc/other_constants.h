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

#pragma once

#include <glib.h>

#define VCSFW_STORAGE_TUDOR_PART_ID_SSFS 1
#define VCSFW_STORAGE_TUDOR_PART_ID_HOST 2

#define MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE 0x1
#define MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE_DATA_SIZE 4
#define MIS_IMAGE_METRICS_IMG_QUALITY 0x10000
#define MIS_IMAGE_METRICS_IMG_QUALITY_DATA_SIZE 8

#define IMAGE_QUALITY_THRESHOLD 50

#define PROVISION_STATE_PROVISIONED 3

#define CAPTURE_FLAGS_ENROLL 15
#define CAPTURE_FLAGS_AUTH 7

#define WINBIO_SID_SIZE 76
#define TEMPLATE_ID_SIZE 16

typedef enum {
   OBJ_TYPE_USERS = 1,
   OBJ_TYPE_TEMPLATES = 2,
   OBJ_TYPE_PAYLOADS = 3,
} obj_type_t;

typedef guint8 db2_id_t[TEMPLATE_ID_SIZE];
/* NOTE: user_id is used in place of winbio_sid */
typedef guint8 user_id_t[WINBIO_SID_SIZE];

typedef struct {
   user_id_t user_id;
   db2_id_t template_id;
   guint16 finger_id;

} enrollment_t;
