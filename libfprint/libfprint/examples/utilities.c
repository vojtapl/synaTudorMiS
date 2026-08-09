/*
 * Utilities for example programs
 *
 * Copyright (C) 2019 Marco Trevisan <marco.trevisan@canonical.com>
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

#define FP_COMPONENT "example-utilities"

#include <libfprint/fprint.h>
#include <stdio.h>

#include "utilities.h"

FpDevice *
discover_device (GPtrArray * devices)
{
  FpDevice *dev;
  int i;

  if (!devices->len)
    return NULL;

  if (devices->len == 1)
    {
      i = 0;
    }
  else
    {
      g_print ("Multiple devices found, choose one\n");

      for (i = 0; i < devices->len; ++i)
        {
          dev = g_ptr_array_index (devices, i);
          g_print ("[%d] %s (%s) - driver %s\n", i,
                   fp_device_get_device_id (dev), fp_device_get_name (dev),
                   fp_device_get_driver (dev));
        }

      g_print ("> ");
      if (!scanf ("%d%*c", &i))
        return NULL;

      if (i < 0 || i >= devices->len)
        return NULL;
    }

  dev = g_ptr_array_index (devices, i);
  g_print ("Selected device %s (%s) claimed by %s driver\n",
           fp_device_get_device_id (dev), fp_device_get_name (dev),
           fp_device_get_driver (dev));

  return dev;
}

const char *
finger_to_string (FpFinger finger)
{
  switch (finger)
    {
    case FP_FINGER_LEFT_THUMB:
      return "left thumb";

    case FP_FINGER_LEFT_INDEX:
      return "left index";

    case FP_FINGER_LEFT_MIDDLE:
      return "left middle";

    case FP_FINGER_LEFT_RING:
      return "left ring";

    case FP_FINGER_LEFT_LITTLE:
      return "left little";

    case FP_FINGER_RIGHT_THUMB:
      return "right thumb";

    case FP_FINGER_RIGHT_INDEX:
      return "right index";

    case FP_FINGER_RIGHT_MIDDLE:
      return "right middle";

    case FP_FINGER_RIGHT_RING:
      return "right ring";

    case FP_FINGER_RIGHT_LITTLE:
      return "right little";

    case FP_FINGER_UNKNOWN:
    default:
      return "unknown";
    }
}

FpFinger
finger_chooser (void)
{
  int i = FP_FINGER_UNKNOWN;

  for (i = FP_FINGER_FIRST; i <= FP_FINGER_LAST; ++i)
    g_print ("  [%d] %s\n", (i - FP_FINGER_FIRST), finger_to_string (i));

  g_print ("> ");
  if (!scanf ("%d%*c", &i))
    return FP_FINGER_UNKNOWN;

  i += FP_FINGER_FIRST;

  if (i < FP_FINGER_FIRST || i > FP_FINGER_LAST)
    return FP_FINGER_UNKNOWN;

  return i;
}

gboolean
load_test_persistent_data (FpDevice *dev, GError **error)
{
  const gchar *path = g_getenv ("SYNA_TLSMOC_PERSISTENT_DATA");
  g_autofree gchar *contents = NULL;
  gsize length = 0;

  if (!path)
    return TRUE;

  if (!g_file_get_contents (path, &contents, &length, error))
    return FALSE;

  g_autoptr(GBytes) bytes = g_bytes_new_take (g_steal_pointer (&contents), length);
  g_autoptr(GVariant) value = g_variant_ref_sink (
    g_variant_new_from_bytes (G_VARIANT_TYPE ("(ayays)"), bytes, FALSE));

  if (!g_variant_is_normal_form (value))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Persistent pairing data are not a normal GVariant");
      return FALSE;
    }

  g_object_set (dev, "fpi-persistent-data", value, NULL);
  return TRUE;
}
