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

#include <glib.h>
#include <stdio.h>

#include "fpi-device.h"
#include "fpi-log.h"
#include "utils.h"

const char *status_to_str(guint16 status)
{
  const char *ret;

  switch (status)
  {
    case 0x000: ret = "VCS_RESULT_OK_1"; break;
    case 0x401: ret = "VCS_RESULT_SENSOR_BAD_CMD"; break;
    case 0x403: ret = "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_1"; break;
    case 0x404: ret = "VCS_RESULT_GEN_OPERATION_DENIED_1"; break;
    case 0x405: ret = "VCS_RESULT_GEN_BAD_PARAM_1"; break;
    case 0x406: ret = "VCS_RESULT_GEN_BAD_PARAM_2"; break;
    case 0x407: ret = "VCS_RESULT_GEN_BAD_PARAM_3"; break;
    case 0x412: ret = "VCS_RESULT_OK_2"; break;
    case 0x48c: ret = "UNKNOWN_RESPONSE_ON_WHICH_SEND_AGAIN"; break;
    case 0x509: ret = "VCS_RESULT_MATCHER_MATCH_FAILED"; break;
    case 0x5B6: ret = "VCS_RESULT_SENSOR_FRAME_NOT_READY"; break;
    case 0x5CC: ret = "VCS_RESULT_OK_3"; break;
    case 0x680: ret = "VCS_RESULT_DB_FULL"; break;
    case 0x683: ret = "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2"; break;
    case 0x689: ret = "VCS_RESULT_GEN_OPERATION_DENIED_2"; break;
    case 0x6EA: ret = "RESPONSE_PROCESSING_FRAME"; break;
    case 0x70e: ret = "VCS_RESULT_OK_4"; break;
    case 0x315: ret = "last TLS session was not properly closed"; break;
    default: ret = "generic VCS_RESULT_SENSOR_MALFUNCTIONED";
  }

  return ret;
}

const char *cmd_to_str(guint8 cmd)
{
  const char *ret;

  switch (cmd)
  {
    case 0x01: ret = "VCSFW_CMD_GET_VERSION"; break;
    case 0x05: ret = "VCSFW_CMD_RESET"; break;
    case 0x07: ret = "VCSFW_CMD_PEEK"; break;
    case 0x08: ret = "VCSFW_CMD_POKE"; break;
    case 0x0e: ret = "VCSFW_CMD_PROVISION"; break;
    case 0x10: ret = "VCSFW_CMD_RESET_OWNERSHIP"; break;
    case 0x15: ret = "CMD_TLS_ALERT"; break;
    case 0x19: ret = "VCSFW_CMD_GET_STARTINFO"; break;
    case 0x39: ret = "VCSFW_CMD_LED_EX2"; break;
    case 0x3e: ret = "VCSFW_CMD_STORAGE_INFO_GET"; break;
    case 0x3f: ret = "VCSFW_CMD_STORAGE_PART_FORMAT"; break;
    case 0x40: ret = "VCSFW_CMD_STORAGE_PART_READ"; break;
    case 0x41: ret = "VCSFW_CMD_STORAGE_PART_WRITE"; break;
    case 0x44: ret = "VCSFW_CMD_TLS_DATA"; break;
    case 0x47: ret = "VCSFW_CMD_DB_OBJECT_CREATE"; break;
    case 0x4f: ret = "VCSFW_CMD_TAKE_OWNERSHIP_EX2"; break;
    case 0x50: ret = "VCSFW_CMD_GET_CERTIFICATE_EX"; break;
    case 0x57: ret = "VCSFW_CMD_TIDLE_SET"; break;
    case 0x69: ret = "CMD_BOOTLOADER_MODE_EXIT_OR_ENTER"; break;
    case 0x7d: ret = "VCSFW_CMD_BOOTLDR_PATCH"; break;
    case 0x7f: ret = "VCSFW_CMD_FRAME_READ"; break;
    case 0x80: ret = "VCSFW_CMD_FRAME_ACQ"; break;
    case 0x81: ret = "VCSFW_CMD_FRAME_FINISH"; break;
    case 0x82: ret = "VCSFW_CMD_FRAME_STATE_GET"; break;
    case 0x86: ret = "VCSFW_CMD_EVENT_CONFIG"; break;
    case 0x87: ret = "VCSFW_CMD_EVENT_READ"; break;
    case 0x8b: ret = "VCSFW_CMD_FRAME_STREAM"; break;
    case 0x8e: ret = "VCSFW_CMD_IOTA_FIND"; break;
    case 0x93: ret = "VCSFW_CMD_PAIR"; break;
    case 0x96: ret = "VCSFW_CMD_ENROLL"; break;
    case 0x99: ret = "VCSFW_CMD_IDENTIFY_MATCH"; break;
    case 0x9d: ret = "VCSFW_CMD_GET_IMAGE_METRICS"; break;
    case 0x9e: ret = "VCSFW_CMD_DB2_GET_DB_INFO"; break;
    case 0x9f: ret = "VCSFW_CMD_DB2_GET_OBJECT_LIST"; break;
    case 0xa0: ret = "VCSFW_CMD_DB2_GET_OBJECT_INFO"; break;
    case 0xa1: ret = "VCSFW_CMD_DB2_GET_OBJECT_DATA"; break;
    case 0xa2: ret = "VCSFW_CMD_DB2_WRITE_OBJECT"; break;
    case 0xa3: ret = "VCSFW_CMD_DB2_DELETE_OBJECT"; break;
    case 0xa4: ret = "VCSFW_CMD_DB2_CLEANUP"; break;
    case 0xa5: ret = "VCSFW_CMD_DB2_FORMAT"; break;
    /* case 0xa6:
     *    ret = "yet unnamed cmd";
     *    break;
     */
    case 0xaa: ret = "VCSFW_CMD_RESET_SBL_MODE"; break;
    case 0xac: ret = "VCSFW_CMD_SSO"; break;
    case 0xae: ret = "VCSFW_CMD_OPINFO_GET"; break;
    case 0xaf: ret = "VCSFW_CMD_HW_INFO_GET"; break;
    default: ret = "unknown cmd";
  }

  return ret;
}

gchar *bin2hex(const guint8 *arr, const gsize size)
{
  gchar *output;
  guint char_idx = 0;

  output = g_malloc(3 + 2 * size);

  output[char_idx++] = '0';
  output[char_idx++] = 'x';

  for (int arr_idx = 0; arr_idx < size; arr_idx++)
  {
    sprintf(&output[char_idx], "%02x", arr[arr_idx]);
    char_idx += 2;
  }

  output[char_idx] = '\0';

  return output;
}

void reverse_array(guint8 *arr, gsize size)
{
  gint start = 0;
  gint end = size - 1;
  gint temp;

  while (start < end)
  {
    // Swap the elements at start and end
    temp = arr[start];
    arr[start] = arr[end];
    arr[end] = temp;

    // Move towards the middle
    start++;
    end--;
  }
}

const char *event_type_to_str(guint8 event_type)
{
  const char *ret;
  switch (event_type)
  {
    case 1: ret = "FINGER_DOWN"; break;
    case 2: ret = "FINGER_DOWN"; break;
    case 24: ret = "FRAME_READY"; break;
    default: ret = "not implemented"; break;
  }
  return ret;
}

const char *obj_type_to_str(guint8 obj_type)
{
  const char *ret;
  switch (obj_type)
  {
    case 1: ret = "OBJ_TYPE_USER"; break;
    case 2: ret = "OBJ_TYPE_TEMPLATE"; break;
    case 3: ret = "OBJ_TYPE_PAYLOAD"; break;
    default: ret = "not implemented"; break;
  }
  return ret;
}

GError *set_and_report_error(FpDeviceError device_error, const gchar *msg, ...)
{
  va_list args;
  va_start(args, msg);

  // Create a formatted error message
  g_autofree gchar *formatted_msg = g_strdup_vprintf(msg, args);

  // Now pass the formatted message to the error functions
  GError *error = fpi_device_error_new_msg(device_error, "%s", formatted_msg);
  fp_err("%s", formatted_msg);

  va_end(args);

  return error;
}
