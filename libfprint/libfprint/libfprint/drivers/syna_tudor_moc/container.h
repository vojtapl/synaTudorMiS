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

#include "device.h"
#include <glib.h>

/* id (2) + data_size (4) */
#define CONTAINTER_HEADER_SIZE 6

typedef enum {
   ENROLL_TAG_TEMPLATE_ID = 0,
   ENROLL_TAG_USER_ID = 1,
   ENROLL_TAG_FINGER_ID = 2,
} enroll_tag_t;

typedef struct {
   guint16 id;
   guint32 data_size;
   guint8 *data;
} container_item_t;

gboolean serialize_container(container_item_t *cont, guint cont_cnt,
                             guint8 **serialized, gsize *serialized_size);

gboolean deserialize_container(const guint8 *serialized,
                               const gsize serialized_size,
                               container_item_t **cont, guint *cont_item_cnt);

gboolean get_container_with_id_index(container_item_t *container,
                                     guint container_cnt, guint8 id,
                                     guint *idx);

gboolean get_enrollment_data_from_serialized_container(const guint8 *data,
                                                       const gsize data_size,
                                                       enrollment_t *enrollment,
                                                       GError **error);
