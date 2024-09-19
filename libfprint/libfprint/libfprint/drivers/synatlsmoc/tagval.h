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

typedef struct
{
  GHashTable *vals;
} TagVal;

TagVal *tagval_new (void);
void tagval_free (TagVal *self);
gboolean tagval_new_from_bytes (TagVal **container, guint8 *data, gsize length, GError **error);
void tagval_to_bytes (TagVal *self, guint8 **serialized, gsize *serialized_length);
gboolean tagval_get (TagVal *self, guint16 tag, guint8 **val, gsize *val_size, GError **error);
gboolean tagval_add (TagVal *self, guint16 tag, guint8 *val, guint32 val_size);

typedef struct
{
  GHashTable *hashvals;
} HashTagVal;

HashTagVal *hashtagval_new_from_bytes (guint8 *container, gsize length, GError **error);
void hashtagval_free (HashTagVal *self);
gboolean hashtagval_get (HashTagVal *self, guint16 tag, guint8 **val, gsize *val_size, GError **error);
gboolean hashtagval_check_hashes (HashTagVal *self, GError **error);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (TagVal, tagval_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (HashTagVal, hashtagval_free);
