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

#include "communication.h"
#include "container.c"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-usb-transfer.h"
#include "gnutls/abstract.h"
#include "tls.h"
#include "utils.h"
#include <glib.h>

static gboolean sensor_status_is_result_ok(guint16 status)
{
   return (status == VCS_RESULT_OK_1 || status == VCS_RESULT_OK_2 ||
           status == VCS_RESULT_OK_3 || status == VCS_RESULT_OK_4);
}

static gboolean sensor_status_is_result_bad_param(guint16 status)
{
   return (status == VCS_RESULT_GEN_BAD_PARAM_1 ||
           status == VCS_RESULT_GEN_BAD_PARAM_2 ||
           status == VCS_RESULT_GEN_BAD_PARAM_3);
}

static const char *sensor_status_to_string(guint16 status)
{
   const char *ret;

   switch (status) {
   case 0x000:
      ret = "VCS_RESULT_OK_1";
      break;
   case 0x401:
      ret = "VCS_RESULT_SENSOR_BAD_CMD";
      break;
   case 0x403:
      ret = "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_1";
      break;
   case 0x404:
      ret = "VCS_RESULT_GEN_OPERATION_DENIED_1";
      break;
   case 0x405:
      ret = "VCS_RESULT_GEN_BAD_PARAM_1";
      break;
   case 0x406:
      ret = "VCS_RESULT_GEN_BAD_PARAM_2";
      break;
   case 0x407:
      ret = "VCS_RESULT_GEN_BAD_PARAM_3";
      break;
   case 0x412:
      ret = "VCS_RESULT_OK_2";
      break;
   case 0x48c:
      ret = "UNKNOWN_RESPONSE_ON_WHICH_SEND_AGAIN";
      break;
   case 0x509:
      ret = "VCS_RESULT_MATCHER_MATCH_FAILED";
      break;
   case 0x5B6:
      ret = "VCS_RESULT_SENSOR_FRAME_NOT_READY";
      break;
   case 0x5CC:
      ret = "VCS_RESULT_OK_3";
      break;
   case 0x680:
      ret = "VCS_RESULT_DB_FULL";
      break;
   case 0x683:
      ret = "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2";
      break;
   case 0x689:
      ret = "VCS_RESULT_GEN_OPERATION_DENIED_2";
      break;
   case 0x6EA:
      ret = "RESPONSE_PROCESSING_FRAME";
      break;
   case 0x70e:
      ret = "VCS_RESULT_OK_4";
      break;
   case 0x315:
      ret = "last TLS session was not closed";
      break;
   default:
      ret = "generic VCS_RESULT_SENSOR_MALFUNCTIONED";
   }

   return ret;
}

static const char *cmd_id_to_str(guint8 cmd_id)
{
   const char *ret;

   switch (cmd_id) {
   case 0x01:
      ret = "VCSFW_CMD_GET_VERSION";
      break;
   case 0x05:
      ret = "VCSFW_CMD_RESET";
      break;
   case 0x07:
      ret = "VCSFW_CMD_PEEK";
      break;
   case 0x08:
      ret = "VCSFW_CMD_POKE";
      break;
   case 0x0e:
      ret = "VCSFW_CMD_PROVISION";
      break;
   case 0x10:
      ret = "VCSFW_CMD_RESET_OWNERSHIP";
      break;
   case 0x15:
      ret = "CMD_TLS_ALERT";
      break;
   case 0x19:
      ret = "VCSFW_CMD_GET_STARTINFO";
      break;
   case 0x39:
      ret = "VCSFW_CMD_LED_EX2";
      break;
   case 0x3e:
      ret = "VCSFW_CMD_STORAGE_INFO_GET";
      break;
   case 0x3f:
      ret = "VCSFW_CMD_STORAGE_PART_FORMAT";
      break;
   case 0x40:
      ret = "VCSFW_CMD_STORAGE_PART_READ";
      break;
   case 0x41:
      ret = "VCSFW_CMD_STORAGE_PART_WRITE";
      break;
   case 0x44:
      ret = "VCSFW_CMD_TLS_DATA";
      break;
   case 0x47:
      ret = "VCSFW_CMD_DB_OBJECT_CREATE";
      break;
   case 0x4f:
      ret = "VCSFW_CMD_TAKE_OWNERSHIP_EX2";
      break;
   case 0x50:
      ret = "VCSFW_CMD_GET_CERTIFICATE_EX";
      break;
   case 0x57:
      ret = "VCSFW_CMD_TIDLE_SET";
      break;
   case 0x69:
      ret = "CMD_BOOTLOADER_MODE_EXIT_OR_ENTER";
      break;
   case 0x7d:
      ret = "VCSFW_CMD_BOOTLDR_PATCH";
      break;
   case 0x7f:
      ret = "VCSFW_CMD_FRAME_READ";
      break;
   case 0x80:
      ret = "VCSFW_CMD_FRAME_ACQ";
      break;
   case 0x81:
      ret = "VCSFW_CMD_FRAME_FINISH";
      break;
   case 0x82:
      ret = "VCSFW_CMD_FRAME_STATE_GET";
      break;
   case 0x86:
      ret = "VCSFW_CMD_EVENT_CONFIG";
      break;
   case 0x87:
      ret = "VCSFW_CMD_EVENT_READ";
      break;
   case 0x8b:
      ret = "VCSFW_CMD_FRAME_STREAM";
      break;
   case 0x8e:
      ret = "VCSFW_CMD_IOTA_FIND";
      break;
   case 0x93:
      ret = "VCSFW_CMD_PAIR";
      break;
   case 0x96:
      ret = "VCSFW_CMD_ENROLL";
      break;
   case 0x99:
      ret = "VCSFW_CMD_IDENTIFY_MATCH";
      break;
   case 0x9d:
      ret = "VCSFW_CMD_GET_IMAGE_METRICS";
      break;
   case 0x9e:
      ret = "VCSFW_CMD_DB2_GET_DB_INFO";
      break;
   case 0x9f:
      ret = "VCSFW_CMD_DB2_GET_OBJECT_LIST";
      break;
   case 0xa0:
      ret = "VCSFW_CMD_DB2_GET_OBJECT_INFO";
      break;
   case 0xa1:
      ret = "VCSFW_CMD_DB2_GET_OBJECT_DATA";
      break;
   case 0xa2:
      ret = "VCSFW_CMD_DB2_WRITE_OBJECT";
      break;
   case 0xa3:
      ret = "VCSFW_CMD_DB2_DELETE_OBJECT";
      break;
   case 0xa4:
      ret = "VCSFW_CMD_DB2_CLEANUP";
      break;
   case 0xa5:
      ret = "VCSFW_CMD_DB2_FORMAT";
      break;
   /* case 0xa6:
    *    ret = "yet unnamed cmd";
    *    break;
    */
   case 0xaa:
      ret = "VCSFW_CMD_RESET_SBL_MODE";
      break;
   case 0xac:
      ret = "VCSFW_CMD_SSO";
      break;
   case 0xae:
      ret = "VCSFW_CMD_OPINFO_GET";
      break;
   case 0xaf:
      ret = "VCSFW_CMD_HW_INFO_GET";
      break;
   default:
      ret = "unknown cmd";
   }

   return ret;
}

static gboolean synaptics_secure_connect_send(FpiDeviceSynaTudorMoc *self,
                                              guint8 *send_data, gsize send_len,
                                              GError **error)
{
   gboolean ret = TRUE;
   g_autoptr(FpiUsbTransfer) transfer = NULL;

   guint8 *wrapped_data = NULL;
   gsize wrapped_size = 0;

   /* Wrap command if in TLS session */
   if (self->tls.established) {
      BOOL_CHECK(tls_wrap(self, send_data, send_len, &wrapped_data,
                          &wrapped_size, error));
   } else {
      wrapped_data = send_data;
      wrapped_size = send_len;
   }
   fp_dbg("  raw unwrapped req:");
   fp_dbg_large_hex(send_data, send_len);
   fp_dbg("  raw wrapped req:");
   fp_dbg_large_hex(wrapped_data, wrapped_size);

   /* Send data */
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk(transfer, USB_EP_REQUEST, wrapped_size);
   /* TODO: do I understand this correctly */
   transfer->short_is_error = FALSE;
   memcpy(transfer->buffer, wrapped_data, wrapped_size);
   BOOL_CHECK_WITH_REPORT(fpi_usb_transfer_submit_sync(
       transfer, USB_TRANSFER_WAIT_TIMEOUT_MS, error));

error:
   if (self->tls.established && wrapped_data != NULL) {
      g_free(wrapped_data);
   }
   return ret;
}

static gboolean synaptics_secure_connect_recv(FpiDeviceSynaTudorMoc *self,
                                              guint8 **recv_data,
                                              gsize *recv_len,
                                              const gboolean check_status,
                                              GError **error)
{
   gboolean ret = TRUE;
   g_autoptr(FpiUsbTransfer) transfer = NULL;
   *recv_data = NULL;
   guint16 status = 0xffff;

   const int status_header_len = 2;

   /* TLS response is expected to be larger */
   if (self->tls.established) {
      *recv_len += WRAP_RESPONSE_ADDITIONAL_SIZE;
   }

   /* receive data */
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk(transfer, USB_EP_REPLY, *recv_len);
   BOOL_CHECK_WITH_REPORT(fpi_usb_transfer_submit_sync(
       transfer, USB_TRANSFER_WAIT_TIMEOUT_MS, error));

   if (transfer->actual_length < status_header_len) {
      *error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                    "Response transfer was too short");
      ret = FALSE;
      goto error;
   }

   fp_dbg("  Transfer: length: %lu, actual_length: %lu", transfer->length,
          transfer->actual_length);
   fp_dbg("  raw wrapped resp:");
   fp_dbg_large_hex(transfer->buffer, transfer->actual_length);

   /* Unwrap command if in TLS session */
   if (self->tls.established && transfer->actual_length != status_header_len) {
      BOOL_CHECK(tls_unwrap(self, transfer->buffer, transfer->actual_length,
                            recv_data, recv_len, error));
   } else {
      /* Response can be shorter, e.g. on error */
      *recv_len = transfer->actual_length;
      *recv_data = g_malloc(*recv_len);
      memcpy(*recv_data, transfer->buffer, transfer->actual_length);
   }

   fp_dbg("  raw unwrapped resp:");
   fp_dbg_large_hex(*recv_data, *recv_len);

   status = FP_READ_UINT16_LE(*recv_data);
   if ((check_status) && !sensor_status_is_result_ok(status)) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO, "Device responded with status: 0x%04x aka %s",
          status, sensor_status_to_string(status));
      ret = FALSE;
      goto error;
   }

error:
   if (!ret && *recv_data != NULL) {
      g_free(*recv_data);
      *recv_data = NULL;
   }
   return ret;
}

gboolean synaptics_secure_connect(FpiDeviceSynaTudorMoc *self,
                                  guint8 *send_data, gsize send_len,
                                  guint8 **recv_data, gsize *recv_len,
                                  const gboolean check_status, GError **error)
{
   gboolean ret = TRUE;

   guint8 cmd_id = send_data[0];

   fp_dbg("---> 0x%x = %s", cmd_id, cmd_id_to_str(cmd_id));
   BOOL_CHECK(synaptics_secure_connect_send(self, send_data, send_len, error));
   BOOL_CHECK(synaptics_secure_connect_recv(self, recv_data, recv_len,
                                            check_status, error));
   fp_dbg("<--- 0x%x = %s", cmd_id, cmd_id_to_str(cmd_id));

error:
   return ret;
}

/* VCSFW_CMD_GET_VERSION =================================================== */

static gboolean parse_get_version(FpiByteReader *reader, get_version_t *result)
{
   gboolean read_ok = TRUE;

   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->build_time);
   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->build_num);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->version_major);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->version_minor);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->target);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->product_id);

   read_ok &= fpi_byte_reader_get_uint8(reader, &result->silicon_revision);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->formal_release);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->platform);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->patch);
   const guint8 *to_copy;
   read_ok &= fpi_byte_reader_get_data(reader, sizeof(result->serial_number),
                                       &to_copy);
   if (read_ok) {
      memcpy(result->serial_number, to_copy, sizeof(result->serial_number));
   }
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &result->security);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->interface);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 7);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->device_type);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 2);
   read_ok &= fpi_byte_reader_get_uint8(reader, &result->provision_state);

   /* sanity check that all has been read */
   if (read_ok) {
      g_assert(fpi_byte_reader_get_pos(reader) == 38);
   }

   return read_ok;
}

static void fp_dbg_get_version(get_version_t *get_version)
{
   fp_dbg("Get version data:");
   fp_dbg("\tBuild Time: %d", get_version->build_time);
   fp_dbg("\tBuild Num: %d", get_version->build_num);
   fp_dbg("\tVersion: %d.%d", get_version->version_major,
          get_version->version_minor);
   fp_dbg("\tTarget: %d", get_version->target);
   fp_dbg("\tProduct: %c", get_version->product_id);
   fp_dbg("\tSilicon revision: %d", get_version->silicon_revision);
   fp_dbg("\tFormal release: %d", get_version->formal_release);
   fp_dbg("\tPlatform: %d", get_version->platform);
   fp_dbg("\tPatch: %d", get_version->patch);

   fp_dbg("\tSerial number:");
   fp_dbg_large_hex(get_version->serial_number,
                    sizeof(get_version->serial_number));
   fp_dbg("\tSecurity: 0x%x", get_version->security);
   fp_dbg("\tInterface: 0x%x", get_version->interface);
   fp_dbg("\tDevice type: 0x%x", get_version->device_type);
   fp_dbg("\tProvision state: %d", get_version->provision_state);
}

gboolean send_get_version(FpiDeviceSynaTudorMoc *self, get_version_t *resp,
                          GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 1;
   gsize recv_size = 38;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_GET_VERSION;

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, sizeof(guint16));
   read_ok &= parse_get_version(&reader, resp);

   if (!read_ok) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Transfer in version response to version query was too short");
      ret = FALSE;
      goto error;
   }

   fp_dbg_get_version(resp);

error:
   return ret;
}

/* VCSFW_CMD_SEND_FRAME_ACQ ================================================ */

gboolean send_frame_acq(FpiDeviceSynaTudorMoc *self,
                        capture_flags_t frame_flags, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 17;
   gsize recv_size = 2;

   const int no_retries = 3;
   const guint32 num_frames = 1;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   /* As there were only two capture flags used, I simplified the request logic
    * a bit */
   send_data[0] = VCSFW_CMD_FRAME_ACQ;
   /* I was unable to find the meaning of these values, so I did not abstract
    * them into constants */
   if (frame_flags == CAPTURE_FLAGS_AUTH) {
      FP_WRITE_UINT32_LE(&(send_data[1]), 4116);
   } else {
      FP_WRITE_UINT32_LE(&(send_data[1]), 12);
   }
   FP_WRITE_UINT32_LE(&(send_data[5]), num_frames);
   FP_WRITE_UINT16_LE(&(send_data[9]), 1);
   send_data[10] = 0;
   send_data[11] = 0;
   send_data[12] = 8;
   send_data[13] = 1;
   send_data[14] = 1;
   send_data[15] = 1;
   /* As there were only two capture flags used, I simplified the request logic
    * a bit */
   send_data[16] = 0;

   guint16 status;
   for (int i = 0; i < no_retries; ++i) {
      /* Do not check the response status as there is a status on which we
       * should send the command again */
      BOOL_CHECK(synaptics_secure_connect(
          self, send_data, send_size, &recv_data, &recv_size, FALSE, error));

      status = FP_READ_UINT16_LE(recv_data);
      if (sensor_status_is_result_ok(status)) {
         break;
      } else if (status == RESPONSE_PROCESSING_FRAME) {
         fp_dbg("received status RESPONSE_PROCESSING_FRAME, retrying");
         continue;
      } else {
         fp_warn("Received status 0x%04x aka %s", status,
                 sensor_status_to_string(status));
         *error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                       "Received status 0x%04x aka %s", status,
                                       sensor_status_to_string(status));
         ret = FALSE;
         goto error;
      }
   }

error:
   return ret;
}

/* VCSFW_CMD_FRAME_FINISH ================================================== */

gboolean send_frame_finish(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 1;
   gsize recv_size = 2;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_FRAME_FINISH;

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

error:
   return ret;
}

/* VCSFW_CMD_ENROLL ======================================================== */

gboolean send_enroll_start(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   /* Unused parameters of original function*/
   const gsize nonce_buffer_size = 0;

   const gsize send_size = 13;
   gsize recv_size = 5;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   /* offset +0 */
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
   /* offset +1 */
   fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_START);
   /* deduced name */
   const guint32 send_nonce_buffer = nonce_buffer_size != 0;
   /* offset +5 */
   fpi_byte_writer_put_uint32_le(&writer, send_nonce_buffer);
   /* offset +9 */
   fpi_byte_writer_put_uint32_le(&writer, nonce_buffer_size);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   /* no need to parse nonce buffer as it it not used here */

error:
   return ret;
}

static gboolean parse_enroll_stats(FpiByteReader *reader,
                                   enroll_stats_t *result)
{
   gboolean read_ok = TRUE;

   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 2);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &result->progress);
   read_ok &= fpi_byte_reader_skip(reader, 16);
   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->quality);
   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->redundant);
   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->rejected);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 4);
   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->template_cnt);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &result->enroll_quality);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 6);
   read_ok &= fpi_byte_reader_get_uint32_le(reader, &result->status);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 4);
   read_ok &= fpi_byte_reader_get_uint32_le(
       reader, &result->smt_like_has_fixed_pattern);

   return read_ok;
}

static void fp_dbg_enroll_stats(enroll_stats_t *enroll_stats)
{
   fp_dbg("Enroll stats:");
   fp_dbg("\tprogress: %d", enroll_stats->progress);
   fp_dbg("\tquality: %d", enroll_stats->quality);
   fp_dbg("\tredundant: %d", enroll_stats->redundant);
   fp_dbg("\trejected: %d", enroll_stats->rejected);
   fp_dbg("\ttemplate count: %d", enroll_stats->template_cnt);
   fp_dbg("\tenroll quality: %d", enroll_stats->enroll_quality);
   fp_dbg("\tenroll status: %d", enroll_stats->status);
   fp_dbg("\tsmt like has fixed pattern: %d",
          enroll_stats->smt_like_has_fixed_pattern);
}

gboolean send_enroll_add_image(FpiDeviceSynaTudorMoc *self,
                               enroll_stats_t *enroll_stats, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 5;
   gsize recv_size = 82;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   /* offset +0 */
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
   /* offset +1 */
   fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_ADD_IMAGE);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   const guint8 *template_id_offset = NULL;
   guint32 enroll_stat_buffer_size;
   guint16 status;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   read_ok &=
       fpi_byte_reader_get_data(&reader, DB2_ID_SIZE, &template_id_offset);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &enroll_stat_buffer_size);
   if (read_ok && enroll_stat_buffer_size != 60) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "qm struct size mismatch - expected: %u, got: %u", 60,
          enroll_stat_buffer_size);
      ret = FALSE;
      goto error;
   }
   read_ok &= parse_enroll_stats(&reader, enroll_stats);
   READ_OK_CHECK(read_ok);

   fp_dbg_enroll_stats(enroll_stats);

   /* template_id is only given when progress is 100% */
   if (enroll_stats->progress == 100) {
      memcpy(enroll_stats->template_id, template_id_offset,
             sizeof(enroll_stats->template_id));

      fp_dbg("\tenroll template_id:");
      fp_dbg_large_hex(enroll_stats->template_id, DB2_ID_SIZE);
   }

error:
   return ret;
}

gboolean send_enroll_commit(FpiDeviceSynaTudorMoc *self,
                            guint8 *enroll_commit_data,
                            gsize enroll_commit_data_size, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 13 + enroll_commit_data_size;
   gsize recv_size = 2;

   g_assert((enroll_commit_data_size != 0) && (enroll_commit_data != NULL));

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *send_data = g_malloc(send_size);

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   /* offset +0 */
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
   /* offset +1 */
   written &= fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_COMMIT);
   /* offset +5 */
   written &= fpi_byte_writer_put_uint32_le(&writer, 0);
   /* offset +9 */
   written &= fpi_byte_writer_put_uint32_le(&writer, enroll_commit_data_size);
   /* offset +13 */
   written &= fpi_byte_writer_put_data(&writer, enroll_commit_data,
                                       enroll_commit_data_size);
   WRITTEN_CHECK(written);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));
error:
   return ret;
}

gboolean add_enrollment(FpiDeviceSynaTudorMoc *self, guint8 *user_id,
                        guint8 finger_id, db2_id_t template_id, GError **error)
{
   gboolean ret = TRUE;

   guint container_cnt = 3;
   container_item_t container[3];

   container[0].id = ENROLL_TAG_TEMPLATE_ID;
   container[0].data = template_id;
   container[0].data_size = DB2_ID_SIZE;

   container[1].id = ENROLL_TAG_USER_ID;
   container[1].data = user_id;
   container[1].data_size = sizeof(user_id_t);

   container[2].id = ENROLL_TAG_FINGER_ID;
   container[2].data = &finger_id;
   container[2].data_size = sizeof(finger_id);

   fp_dbg("Adding enrollment with:");
   fp_dbg("\ttemplate ID:");
   fp_dbg_large_hex(template_id, DB2_ID_SIZE);
   fp_dbg("\tuser ID:");
   fp_dbg_large_hex(user_id, sizeof(user_id_t));
   fp_dbg("\tfinger ID: %u", finger_id);

   g_autofree guint8 *enroll_commit_data = NULL;
   gsize enroll_commit_data_size = 0;
   BOOL_CHECK(serialize_container(container, container_cnt, &enroll_commit_data,
                                  &enroll_commit_data_size));

   fp_dbg("serialized container:");
   fp_dbg_large_hex(enroll_commit_data, enroll_commit_data_size);

   BOOL_CHECK(send_enroll_commit(self, enroll_commit_data,
                                 enroll_commit_data_size, error));

error:
   return ret;
}

gboolean send_enroll_finish(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 5;
   gsize recv_size = 2;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_ENROLL;
   FP_WRITE_UINT32_LE(&send_data[1], ENROLL_SUBCMD_FINISH);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

error:
   return ret;
}

/* VCSFW_CMD_IDENTIFY_MATCH ================================================ */

gboolean send_identify_match(FpiDeviceSynaTudorMoc *self,
                             db2_id_t *template_ids_to_match,
                             gsize number_of_template_ids, gboolean *matched,
                             enrollment_t *match, GError **error)
{
   gboolean ret = TRUE;

   g_assert(self->tls.established);

   /*unused argument*/
   const gsize data_2_size = 0;
   const guint8 *data_2 = NULL;

   const guint8 *z_data = NULL;

   /*send only one type of data*/
   g_assert(((data_2_size == 0) && (data_2 == NULL)) ||
            ((number_of_template_ids == 0) && (template_ids_to_match == 0)));

   const gsize template_id_array_byte_size =
       sizeof(*template_ids_to_match) * number_of_template_ids;
   const gsize send_size = 13 + data_2_size + template_id_array_byte_size;
   gsize recv_size = 1602;

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *send_data = g_malloc(send_size);

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   /* offset +0 */
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_IDENTIFY_MATCH);
   /* offset +1 */
   written &=
       fpi_byte_writer_put_uint32_le(&writer, VCSFW_CMD_IDENTIFY_WBF_MATCH);
   /* offset +5 */
   written &= fpi_byte_writer_put_uint32_le(&writer, data_2_size);
   /* offset +9 */
   written &= fpi_byte_writer_put_uint32_le(&writer, number_of_template_ids);
   WRITTEN_CHECK(written);

   if (template_ids_to_match != NULL) {
      /* offset +13 */
      fpi_byte_writer_put_data(&writer, *template_ids_to_match,
                               number_of_template_ids *
                                   template_id_array_byte_size);
   } else if (data_2 != NULL) {
      /* offset +13 */
      fpi_byte_writer_put_data(&writer, data_2, data_2_size);
   }

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, FALSE, error));

   guint16 status = 0;

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   /* VCS_RESULT_MATCHER_MATCH_FAILED given on identifiy fail
    * VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 given on verify fail */
   if (status == VCS_RESULT_MATCHER_MATCH_FAILED ||
       status == VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2) {
      fp_dbg("Received status 0x%04x aka match fail", status);
      *matched = FALSE;
      goto error;
   } else if (!sensor_status_is_result_ok(status)) {
      fp_err("%s received error status: 0x%4x aka %s", __FUNCTION__, status,
             sensor_status_to_string(status));
      goto error;
   }
   guint32 match_stats_len = 0;
   /* exact names are not known */
   guint32 y_len = 0;
   guint32 z_len = 0;
   /* we do not read this template id as it is sent serialized  in z_data and
    * from testing it always matches */
   /* offset +2 */
   read_ok &= fpi_byte_reader_skip(&reader, DB2_ID_SIZE);
   /* offset +18 */
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &match_stats_len);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &y_len);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &z_len);
   /* do not read match stats as what is interpretable is not useful */
   read_ok &= fpi_byte_reader_skip(&reader, MATCH_STATS_SIZE);
   read_ok &= fpi_byte_reader_get_data(&reader, z_len, &z_data);

   READ_OK_CHECK(read_ok);

   if (y_len != 0 || z_len == 0) {
      fp_err("received unimplemented identify message with y_len=%d, z_len=%d",
             y_len, z_len);
      goto error;
   }

   if (match_stats_len != MATCH_STATS_SIZE) {
      fp_err("qm struct size mismatch!");
      goto error;
   }

   *matched = TRUE;

   BOOL_CHECK(get_enrollment_data_from_serialized_container(z_data, z_len,
                                                            match, error));

error:
   return ret;
}

/* VCSFW_CMD_GET_IMAGE_METRICS ============================================= */

gboolean send_get_image_metrics(FpiDeviceSynaTudorMoc *self, img_metrics_t type,
                                guint32 *recv_value, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 5;
   gsize recv_size = 10;

   g_assert(type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE ||
            type == MIS_IMAGE_METRICS_IMG_QUALITY);

   if (type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE) {
      recv_size = 14;
   } else if (type == MIS_IMAGE_METRICS_IMG_QUALITY) {
      recv_size = 70;
   }

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_GET_IMAGE_METRICS;
   FP_WRITE_UINT32_LE(&send_data[1], type);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   if (recv_size < 3) {
      fp_err("Image metrics 0x%x were unsupported by sensor", type);
      goto error;
   }

   FpiByteReader reader;
   gboolean read_ok = TRUE;
   guint32 received_img_metrics = 0;
   guint32 recv_data_size = 0;

   fpi_byte_reader_init(&reader, recv_data, recv_size);
   /* we do not need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &received_img_metrics);
   g_assert(received_img_metrics == type);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &recv_data_size);
   READ_OK_CHECK(read_ok);

   if (recv_data_size == 0) {
      fp_err("Unable to query img metrics now");
   } else if (type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE &&
              recv_data_size ==
                  MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE_DATA_SIZE) {
      /*read IPL finger coverage*/
      read_ok &= fpi_byte_reader_get_uint32_le(&reader, recv_value);
      READ_OK_CHECK(read_ok);
      fp_dbg("Image finger IPL coverage is %u of sensor", *recv_value);
   } else if (type == MIS_IMAGE_METRICS_IMG_QUALITY &&
              recv_data_size == MIS_IMAGE_METRICS_IMG_QUALITY_DATA_SIZE) {
      /* read image quality coverage */
      read_ok &= fpi_byte_reader_get_uint32_le(&reader, recv_value);
      READ_OK_CHECK(read_ok);
      /* not reading the other 4 bytes as the interpretation is unknown */
      fp_dbg("Image finger quality is %u%%", *recv_value);
   } else {
      fp_err("Image metrics 0x%x were not supported; got %u bytes as data size",
             type, recv_data_size);
   }

error:
   return ret;
}

/* VCSFW_CMD_EVENT_CONFIG ================================================== */

gboolean send_event_config(FpiDeviceSynaTudorMoc *self, guint32 event_mask,
                           GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 37;
   gsize recv_size = 66;

   const gint event_mask_cnt = 8;

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *send_data = g_malloc(send_size);

   fp_dbg("Setting event mask to: 0b%b", event_mask);

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_EVENT_CONFIG);
   /* repeat event mask 8 times */
   for (gint i = 0; i < event_mask_cnt; ++i) {
      fpi_byte_writer_put_uint32_le(&writer, event_mask);
   }
   if (event_mask == 0) {
      fpi_byte_writer_put_uint32_le(&writer, 4);
   } else {
      fpi_byte_writer_put_uint32_le(&writer, 0);
   }

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   if (recv_size < 66) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Transfer in version response to version query was too short");
      goto error;
   }

   fp_dbg("Set event mask to %b", event_mask);

   guint32 event_seq_num = FP_READ_UINT16_LE(&recv_data[64]);
   fp_dbg("Current event sequence number is %d", event_seq_num);

error:
   return ret;
}

/* VCSFW_CMD_EVENT_READ ==================================================== */

gboolean send_event_read(FpiDeviceSynaTudorMoc *self, guint32 *recv_event_mask,
                         GError **error)
{
   gboolean ret = TRUE;

   const guint16 max_num_events_in_resp = 32;

   gsize send_size = 9;
   gsize recv_size = 6 + 12 * max_num_events_in_resp;

   guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_EVENT_READ;
   FP_WRITE_UINT16_LE(&send_data[3], max_num_events_in_resp);

   do {
      /*is here as we need to update the sequence number*/
      FP_WRITE_UINT16_LE(&send_data[1], self->events.seq_num);

      if (!self->events.read_in_legacy_mode) {
         FP_WRITE_UINT32_LE(&send_data[5], 1);
      } else {
         /* shorten message if fallen back to legacy mode */
         send_size = 5;
      }

      // clean up after last iteration
      if (recv_data != NULL) {
         g_free(recv_data);
         recv_data = NULL;
      }

      BOOL_CHECK(synaptics_secure_connect(
          self, send_data, send_size, &recv_data, &recv_size, FALSE, error));

      gboolean read_ok = TRUE;
      FpiByteReader reader;
      fpi_byte_reader_init(&reader, recv_data, recv_size);

      guint16 status = 0;
      read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
      if (!sensor_status_is_result_ok(status)) {
         if (sensor_status_is_result_bad_param(status)) {
            fp_dbg("Received status 0x%04x on event read, falling back to "
                   "legacy event reading",
                   status);
            self->events.read_in_legacy_mode = TRUE;
            continue;
         } else {
            *error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                          "received status: 0x%04x", status);

            ret = FALSE;
            goto error;
         }
      }

      guint16 recv_num_events = 0;
      guint16 recv_num_pending_events = 0;
      read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_events);
      read_ok &=
          fpi_byte_reader_get_uint16_le(&reader, &recv_num_pending_events);
      fp_dbg("Received num_events: %d, num_pending_events: %d", recv_num_events,
             recv_num_pending_events);

      /*read event types*/
      for (int i = 0; i < recv_num_events && read_ok; ++i) {
         guint8 event;
         read_ok &= fpi_byte_reader_get_uint8(&reader, &event);
         if (read_ok) {
            *recv_event_mask |= 1 << event;
         }
         /* skip over unknown stuff */
         read_ok &= fpi_byte_reader_skip(&reader, 11);
      }

      if (!read_ok) {
         *error = set_and_report_error(
             FP_DEVICE_ERROR_PROTO,
             "Transfer in version response to event read query was too "
             "short");
         ret = FALSE;
         goto error;
      }

      /* update event sequence number */
      self->events.seq_num = (self->events.seq_num + recv_num_events) & 0xffff;
      fp_dbg("New event sequence number: %d", self->events.seq_num);

      /* parse number of pending events */
      if (self->events.read_in_legacy_mode) {
         g_assert(recv_num_pending_events >= recv_num_events);
         self->events.num_pending = recv_num_pending_events - recv_num_events;
      } else {
         self->events.num_pending = recv_num_pending_events;
      }
   } while (self->events.num_pending > 0);

error:
   if (recv_data != NULL) {
      g_free(recv_data);
   }
   return ret;
}

/* VCSFW_CMD_DB2_INFO ====================================================== */

static gboolean parse_db2_info(FpiByteReader *reader, db2_info_t *db2_info)
{
   gboolean read_ok = TRUE;

   read_ok &= fpi_byte_reader_get_uint16_le(reader, &db2_info->dummy);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &db2_info->version_major);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &db2_info->version_minor);
   read_ok &=
       fpi_byte_reader_get_uint32_le(reader, &db2_info->partition_version);

   read_ok &= fpi_byte_reader_get_uint16_le(reader, &db2_info->uop_length);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &db2_info->top_length);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &db2_info->pop_length);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->template_object_size);
   read_ok &= fpi_byte_reader_get_uint16_le(
       reader, &db2_info->payload_object_slot_size);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->num_current_users);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->num_deleted_users);
   read_ok &= fpi_byte_reader_get_uint16_le(
       reader, &db2_info->num_available_user_slots);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->num_current_templates);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->num_deleted_templates);
   read_ok &= fpi_byte_reader_get_uint16_le(
       reader, &db2_info->num_available_template_slots);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->num_current_payloads);
   read_ok &=
       fpi_byte_reader_get_uint16_le(reader, &db2_info->num_deleted_payloads);
   read_ok &= fpi_byte_reader_get_uint16_le(
       reader, &db2_info->num_available_payload_slots);

   return read_ok;
}

static void fp_dbg_db2_info(db2_info_t *db2_info)
{
   fp_dbg("received DB2 info:");
   fp_dbg("\tdummy: %d", db2_info->dummy);
   fp_dbg("\tversion_major: %d", db2_info->version_major);
   fp_dbg("\tversion_minor: %d", db2_info->version_minor);
   fp_dbg("\tpartition_version: %d", db2_info->partition_version);
   fp_dbg("\tuop_length: %d", db2_info->uop_length);
   fp_dbg("\ttop_length: %d", db2_info->top_length);
   fp_dbg("\tpop_length: %d", db2_info->pop_length);
   fp_dbg("\ttemplate_object_size: %d", db2_info->template_object_size);
   fp_dbg("\tpayload_object_slot_size: %d", db2_info->payload_object_slot_size);
   fp_dbg("\tnum_current_users: %d", db2_info->num_current_users);
   fp_dbg("\tnum_deleted_users: %d", db2_info->num_deleted_users);
   fp_dbg("\tnum_available_user_slots: %d", db2_info->num_available_user_slots);
   fp_dbg("\tnum_current_templates: %d", db2_info->num_current_templates);
   fp_dbg("\tnum_deleted_templates: %d", db2_info->num_deleted_templates);
   fp_dbg("\tnum_available_template_slots: %d ",
          db2_info->num_available_template_slots);
   fp_dbg("\tnum_current_payloads: %d ", db2_info->num_current_payloads);
   fp_dbg("\tnum_deleted_payloads: %d ", db2_info->num_deleted_payloads);
   fp_dbg("\tnum_available_payload_slots: %d",
          db2_info->num_available_payload_slots);
}

/* prints DB2 info on debug output and stores numbers of current users,
 * templates and payloads */
gboolean send_db2_info(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 2;
   gsize recv_size = 64;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_DB2_GET_DB_INFO;
   send_data[1] = 1;

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, sizeof(guint16));
   db2_info_t db2_info;
   read_ok &= parse_db2_info(&reader, &db2_info);
   READ_OK_CHECK(read_ok);

   fp_dbg_db2_info(&db2_info);

   self->storage.num_current_users = db2_info.num_current_users;
   self->storage.num_current_templates = db2_info.num_current_templates;
   self->storage.num_current_payloads = db2_info.num_current_payloads;

error:
   return ret;
}

/* VCSFW_CMD_DB2_FORMAT ==================================================== */

gboolean send_db2_format(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 12;
   gsize recv_size = 8;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_DB2_FORMAT;
   send_data[1] = 1;
   memset(&send_data[2], 0, send_size - 2);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   /* skip over unknown4 */
   read_ok &= fpi_byte_reader_skip(&reader, 4);
   guint new_partition_version = 0;
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &new_partition_version);

   if (!read_ok) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Transfer in version response to version query was too short");
      goto error;
   }
   fp_dbg("Format succeeded with new partition version: %d",
          new_partition_version);

error:
   return ret;
}

/* VCSFW_CMD_DB2_DELETE_OBJECT ============================================= */

gboolean send_db2_delete_object(FpiDeviceSynaTudorMoc *self,
                                const obj_type_t obj_type,
                                const db2_id_t *obj_id, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   gsize recv_size = 4;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_DB2_DELETE_OBJECT;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, DB2_ID_SIZE);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 num_deleted_objects = 0;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_deleted_objects);

   if (!read_ok) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Transfer in to version DB2 delete object was too short");
      goto error;
   }
   fp_dbg("Delete object succeeded with number of deleted objects: %d",
          num_deleted_objects);

error:
   return ret;
}

/* VCSFW_CMD_GET_OBJECT_LIST =============================================== */

static gsize get_object_list_recv_size(FpiDeviceSynaTudorMoc *self,
                                       obj_type_t obj_type)
{
   switch (obj_type) {
   case OBJ_TYPE_USERS:
      return 4 + 16 * self->storage.num_current_users;
      break;
   case OBJ_TYPE_TEMPLATES:
      return 4 + 16 * self->storage.num_current_templates;
      break;
   case OBJ_TYPE_PAYLOADS:
      return 4 + 16 * self->storage.num_current_payloads;
      break;
   }

   return 0;
}

gboolean send_db2_get_object_list(FpiDeviceSynaTudorMoc *self,
                                  const obj_type_t obj_type,
                                  const db2_id_t obj_id, db2_id_t **obj_array,
                                  guint16 *obj_array_len, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   gsize recv_size;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   /* update numbers of current db2 items in database */
   BOOL_CHECK(send_db2_info(self, error));
   recv_size = get_object_list_recv_size(self, obj_type);

   send_data[0] = VCSFW_CMD_DB2_GET_OBJECT_LIST;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, DB2_ID_SIZE);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, obj_array_len);
   READ_OK_CHECK(read_ok);

   fp_dbg("Object id");
   fp_dbg_large_hex(obj_id, DB2_ID_SIZE);
   fp_dbg("of type %d has object array with %d elements:", obj_type,
          *obj_array_len);

   *obj_array = g_new(db2_id_t, *obj_array_len);

   for (int i = 0; i < *obj_array_len; ++i) {
      const guint8 *obj_id_offset;
      read_ok &= fpi_byte_reader_get_data(&reader, DB2_ID_SIZE, &obj_id_offset);
      if (read_ok) {
         memcpy(&((*obj_array)[i]), obj_id_offset, DB2_ID_SIZE);
         fp_dbg("\tat position %d is:", i);
         fp_dbg_large_hex((*obj_array)[i], DB2_ID_SIZE);
      }
   }

error:
   return ret;
}

/* VCSFW_CMD_DB2_GET_OBJECT_INFO =========================================== */

gboolean send_db2_get_object_info(FpiDeviceSynaTudorMoc *self,
                                  const obj_type_t obj_type,
                                  const db2_id_t obj_id, guint8 **obj_info,
                                  gsize *obj_info_size, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   *obj_info_size = obj_type == OBJ_TYPE_USERS ? 12 : 52;

   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_DB2_GET_OBJECT_INFO;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, DB2_ID_SIZE);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, obj_info,
                                       obj_info_size, TRUE, error));

   fp_dbg("Object with id:");
   fp_dbg_large_hex(obj_id, DB2_ID_SIZE);
   fp_dbg("of type %d has info:", obj_type);
   fp_dbg_large_hex(*obj_info, *obj_info_size);

error:
   if (!ret && *obj_info != NULL) {
      g_free(*obj_info);
      *obj_info = NULL;
   }
   return ret;
}

/* VCSFW_CMD_=============================================================== */

static gboolean get_payload_data_size(FpiDeviceSynaTudorMoc *self,
                                      const db2_id_t payload_id,
                                      guint *payload_data_size, GError **error)
{
   gboolean ret = TRUE;

   g_autofree guint8 *obj_info;
   gsize obj_info_size;
   BOOL_CHECK(send_db2_get_object_info(self, OBJ_TYPE_PAYLOADS, payload_id,
                                       &obj_info, &obj_info_size, error));

   if (obj_info_size < 50) {
      fp_err("Received too short object info - expected %d, got %lu", 50,
             obj_info_size);
      goto error;
   }

   *payload_data_size = FP_READ_UINT32_LE(&obj_info[48]);
   fp_dbg("Object with id:");
   fp_dbg_large_hex(payload_id, DB2_ID_SIZE);
   fp_dbg("of type %d has payload data size: %d", OBJ_TYPE_PAYLOADS,
          *payload_data_size);

error:
   return ret;
}

gboolean send_db2_get_object_data(FpiDeviceSynaTudorMoc *self,
                                  const obj_type_t obj_type,
                                  const db2_id_t obj_id, guint8 **obj_data,
                                  guint *obj_data_size, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   gsize recv_size;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   /* update num_current_users */
   BOOL_CHECK(send_db2_info(self, error));
   if (obj_type == OBJ_TYPE_USERS) {
      recv_size = 8;
      fp_warn("get_object_data is untested for OBJ_TYPE_USERS");
   } else {
      BOOL_CHECK(get_payload_data_size(self, obj_id, obj_data_size, error));
      recv_size = 8 + *obj_data_size;
   }

   g_assert(*obj_data_size < 65535);

   send_data[0] = VCSFW_CMD_DB2_GET_OBJECT_DATA;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, DB2_ID_SIZE);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, obj_data_size);
   fp_dbg("Received object data of length %u", *obj_data_size);
   read_ok &= fpi_byte_reader_dup_data(&reader, *obj_data_size, obj_data);

   READ_OK_CHECK(read_ok);

error:
   return ret;
}

/* Read events ============================================================= */

gboolean get_event_data(FpiDeviceSynaTudorMoc *self, guint8 *event_buffer,
                        const gsize event_buffer_size, GError **error)
{
   gboolean ret = TRUE;

   const guint8 recv_size = 7;
   g_assert(event_buffer_size >= recv_size);

   g_autoptr(FpiUsbTransfer) transfer = NULL;

   /* receive data */
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk(transfer, USB_EP_INTERRUPT, event_buffer_size);
   if (!fpi_usb_transfer_submit_sync(transfer, USB_TRANSFER_WAIT_TIMEOUT_MS,
                                     error)) {
      if ((*error)->code == G_USB_DEVICE_ERROR_TIMED_OUT) {
         fp_dbg("%s in %s", (*error)->message, __FUNCTION__);
      } else {
         fp_err("%s: %s: %d: Error in fpi_usb_transfer_submit_sync: %d",
                __FILE__, __FUNCTION__, __LINE__, (*error)->code);
      }

      ret = FALSE;
      goto error;
   }

   fp_dbg("get_event_data raw resp:");
   fp_dbg_large_hex(transfer->buffer, transfer->actual_length);

   if (transfer->actual_length > event_buffer_size) {
      fp_warn("Unexpected length of response in %s, got: %lu, expected: %lu, "
              "received array: ",
              __func__, transfer->actual_length, event_buffer_size);
      fp_dbg_large_hex(transfer->buffer, transfer->actual_length);
   }

   memcpy(event_buffer, transfer->buffer, transfer->actual_length);

error:
   return ret;
}

gboolean wait_for_events_blocking(FpiDeviceSynaTudorMoc *self,
                                  guint32 event_mask, GError **error)
{
   gboolean ret = TRUE;
   /*
    * Needs to be larger than 7 as that is the size of response for
    * get_event_data */
   const gsize event_buffer_size = 16;
   guint8 event_buffer[event_buffer_size];

   guint32 recv_event_mask = 0;
   while ((recv_event_mask & event_mask) != event_mask) {
      if (g_cancellable_is_cancelled(self->cancellable)) {
         fp_warn("Received cancellation event, stopping waiting for events");
         ret = FALSE;
         goto error;
      }

      if (self->events.num_pending <= 0) {
         fp_info("Waiting for sensor to have events");
         while (TRUE) {
            if (!get_event_data(self, event_buffer, event_buffer_size, error)) {
               if ((*error)->code == G_USB_DEVICE_ERROR_TIMED_OUT) {
                  /* timeout is not considered an error here */
                  *error = NULL;
                  continue;
               } else {
                  fp_err("Error in get_event_data: %d", __LINE__);
                  ret = FALSE;
                  goto error;
               }
            }
            /* we will read the events in the next part, here just read the
             * event sequence number */
            guint16 recv_event_seq_num = FP_READ_UINT16_LE(&event_buffer[6]);
            if (self->events.num_pending != recv_event_seq_num) {
               break;
            }
         }
      }

      fp_info("Reading sensor events");
      fp_dbg("Num pending bevents: %d", self->events.num_pending);
      BOOL_CHECK(send_event_read(self, &recv_event_mask, error));
      fp_dbg("Num pending aevents: %d", self->events.num_pending);
      fp_dbg("Recv event mask is: %b, requested is: %b", recv_event_mask,
             event_mask);
   }

error:
   return ret;
}

/* ========================================================================= */

/*
 * Sends a get_version command to force the sensor to close its TLS session
 * -> error 0x315 is expected (its real name is not known) */
gboolean send_cmd_to_force_close_sensor_tls_session(FpiDeviceSynaTudorMoc *self,
                                                    GError **error)
{
   gboolean ret = TRUE;

   /* deduced name */
   const guint16 unclosed_tls_session_status = 0x315;

   const gsize send_size = 1;
   /* we may get a TLS alert message, so increase the recv_size accordingly */
   gsize recv_size = 38 + WRAP_RESPONSE_ADDITIONAL_SIZE;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_GET_VERSION;

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, FALSE, error));

   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   if (recv_size < 2) {
      *error =
          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                               "Response to get_version command was too short");
      ret = FALSE;
      goto error;
   }

   guint16 status = FP_READ_UINT16_LE(recv_data);
   if (sensor_status_is_result_ok(status)) {
      fp_dbg("TLS force close - sensor was not in TLS session");
   } else if (status == unclosed_tls_session_status) {
      fp_dbg("TLS force close - sensor was in TLS status");
   } else {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO, "Device responded with error: 0x%04x aka %s",
          status, sensor_status_to_string(status));
   }

error:
   return ret;
}

static gboolean write_dft(FpiDeviceSynaTudorMoc *self, guint8 *data,
                          gsize data_size, GError **error)
{
   gboolean ret = TRUE;

   fp_dbg("---> DFT");
   fp_dbg_large_hex(data, data_size);

   /* Send data */
   g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_control(
       transfer, G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
       G_USB_DEVICE_REQUEST_TYPE_VENDOR, G_USB_DEVICE_RECIPIENT_DEVICE,
       REQUEST_DFT_WRITE, 0, 0, data_size);

   transfer->short_is_error = FALSE;
   memcpy(transfer->buffer, data, data_size);

   BOOL_CHECK_WITH_REPORT(fpi_usb_transfer_submit_sync(
       transfer, USB_TRANSFER_WAIT_TIMEOUT_MS, error));

error:
   return ret;
}

/* Bootloader functions ==================================================== */

gboolean sensor_is_in_bootloader_mode(FpiDeviceSynaTudorMoc *self)
{
   return self->mis_version.product_id == PRODUCT_ID_BOOTLOADER_1 ||
          self->mis_version.product_id == PRODUCT_ID_BOOTLOADER_2;
}

static gboolean send_bootloader_mode_exit(FpiDeviceSynaTudorMoc *self,
                                          GError **error)
{
   gboolean ret = TRUE;

   fp_dbg("Exiting bootloader mode");

   guint8 to_send[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   BOOL_CHECK(write_dft(self, to_send, sizeof(to_send), error));

   g_usb_device_reset(fpi_device_get_usb_device(FP_DEVICE(self)), error);

error:
   return ret;
}

static gboolean send_bootloader_mode_enter(FpiDeviceSynaTudorMoc *self,
                                           GError **error)
{
   gboolean ret = TRUE;

   fp_dbg("Entering bootloader mode");

   guint8 to_send[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
   BOOL_CHECK(write_dft(self, to_send, sizeof(to_send), error));
   g_usb_device_reset(fpi_device_get_usb_device(FP_DEVICE(self)), error);

error:
   return ret;
}

gboolean exit_bootloader_mode(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   BOOL_CHECK(send_bootloader_mode_exit(self, error));
   /* update MiS version data which contain if sensor is in bootloader mode */
   BOOL_CHECK(send_get_version(self, &self->mis_version, error));

   if (sensor_is_in_bootloader_mode(self)) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO, "Unable to get sensor out of bootloader mode, "
                                 "it may not have a valid firmware");
      ret = FALSE;
   }

error:
   return ret;
}

/* VCSFW_CMD_PAIR ========================================================== */

gboolean send_pair(FpiDeviceSynaTudorMoc *self,
                   const guint8 *send_host_cert_bytes, GError **error)
{
   g_return_val_if_fail(send_host_cert_bytes != NULL, FALSE);

   gboolean ret = TRUE;

   const gsize send_len = 1 + CERTIFICATE_SIZE;
   gsize recv_len = 802; /* 2 * CERTIFICATE_SIZE + status_header_len */

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *to_send = g_malloc(send_len);

   to_send[0] = VCSFW_CMD_PAIR;
   memcpy(&to_send[1], send_host_cert_bytes, CERTIFICATE_SIZE);

   BOOL_CHECK(synaptics_secure_connect(self, to_send, send_len, &recv_data,
                                       &recv_len, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_len);
   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   const guint8 *recv_host_cert_bytes = NULL;
   read_ok &= fpi_byte_reader_get_data(&reader, CERTIFICATE_SIZE,
                                       &recv_host_cert_bytes);
   const guint8 *sensor_cert_bytes = NULL;
   read_ok &=
       fpi_byte_reader_get_data(&reader, CERTIFICATE_SIZE, &sensor_cert_bytes);
   READ_OK_CHECK(read_ok);

   BOOL_CHECK(parse_certificate(recv_host_cert_bytes, CERTIFICATE_SIZE,
                                &self->pairing_data.host_cert));
   BOOL_CHECK(parse_certificate(sensor_cert_bytes, CERTIFICATE_SIZE,
                                &self->pairing_data.sensor_cert));

   if (self->pairing_data.private_key_initialized) {
      self->pairing_data.present = TRUE;
   } else {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Private key is not initialized when it should be");
      ret = FALSE;
   }

error:
   return ret;
}

/* VCSFW_CMD_STORAGE_PART_READ ============================================= */

static gboolean send_storage_read(FpiDeviceSynaTudorMoc *self,
                                  storage_partition_t partition, gsize offset,
                                  gsize read_size, guint8 **data,
                                  guint32 *data_size, GError **error)
{
   gboolean ret = TRUE;

   const gsize send_len = 13;
   gsize recv_len = 8 + read_size;

   g_autofree guint8 *recv_data = NULL;
   guint8 to_send[send_len];

   *data = NULL;

   /* unused parameters */
   const guint16 param_2 = 0;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, to_send, send_len, FALSE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_STORAGE_PART_READ);
   written &= fpi_byte_writer_put_uint8(&writer, partition);
   written &= fpi_byte_writer_put_uint8(&writer, param_2);
   written &= fpi_byte_writer_put_uint16_le(&writer, 0xffff);
   written &= fpi_byte_writer_put_uint32_le(&writer, offset);
   written &= fpi_byte_writer_put_uint32_le(&writer, read_size);
   WRITTEN_CHECK(written);

   BOOL_CHECK(synaptics_secure_connect(self, to_send, send_len, &recv_data,
                                       &recv_len, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_len);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, data_size);
   /* skip over unused / unknown */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_dup_data(&reader, *data_size, data);
   READ_OK_CHECK(read_ok);

error:
   return ret;
}

gboolean read_host_partition(FpiDeviceSynaTudorMoc *self, guint8 **data,
                             guint32 *data_size, GError **error)
{
   return send_storage_read(self, VCSFW_STORAGE_TUDOR_PART_ID_HOST, 0, 0x1000,
                            data, data_size, error);
}

/* VCSFW_CMD_STORAGE_PART_WRITE ============================================ */

static gboolean send_storage_write(FpiDeviceSynaTudorMoc *self,
                                   storage_partition_t partition, gsize offset,
                                   guint8 *data, gsize data_size,
                                   GError **error)
{
   gboolean ret = TRUE;

   g_return_val_if_fail(self->tls.established, FALSE);

   const gsize send_len = 13 + data_size;
   gsize recv_len = 6;
   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *to_send = g_malloc(send_len);

   /* unused parameters */
   const guint16 param_2 = 0;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, to_send, send_len, FALSE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_STORAGE_PART_WRITE);
   written &= fpi_byte_writer_put_uint8(&writer, partition);
   written &= fpi_byte_writer_put_uint8(&writer, param_2);
   written &= fpi_byte_writer_put_uint16_le(&writer, 0xffff);
   written &= fpi_byte_writer_put_uint32_le(&writer, offset);
   written &= fpi_byte_writer_put_uint32_le(&writer, data_size);
   written &= fpi_byte_writer_put_data(&writer, data, data_size);
   WRITTEN_CHECK(written);

   BOOL_CHECK(synaptics_secure_connect(self, to_send, send_len, &recv_data,
                                       &recv_len, TRUE, error));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_len);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   guint32 written_size = 0;
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &written_size);
   READ_OK_CHECK(read_ok);

   if (written_size != data_size) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Written_size: %u does not match data_to_write_size: %lu",
          written_size, data_size);
      ret = FALSE;
      goto error;
   }

error:
   return ret;
}

gboolean write_host_partition(FpiDeviceSynaTudorMoc *self, guint8 *data,
                              gsize data_size, GError **error)
{
   return send_storage_write(self, VCSFW_STORAGE_TUDOR_PART_ID_HOST, 0, data,
                             data_size, error);
}
