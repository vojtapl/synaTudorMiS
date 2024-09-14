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
#include "tls.h"
#include "utils.h"
#include <glib.h>
#include <gnutls/abstract.h>

#define COMMUNICATION_DEBUG

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

gboolean serialize_enrollment_data(FpiDeviceSynaTudorMoc *self,
                                   enrollment_t *enrollment,
                                   guint8 **serialized, gsize *serialized_size,
                                   GError **error)
{
   gboolean ret = TRUE;

   guint container_cnt = 3;
   container_item_t container[3];

   container[0].id = ENROLL_TAG_TEMPLATE_ID;
   container[0].data = enrollment->template_id;
   container[0].data_size = DB2_ID_SIZE;

   container[1].id = ENROLL_TAG_USER_ID;
   container[1].data = enrollment->user_id;
   container[1].data_size = sizeof(user_id_t);

   container[2].id = ENROLL_TAG_FINGER_ID;
   container[2].data = &enrollment->finger_id;
   container[2].data_size = sizeof(enrollment->finger_id);

   fp_dbg("Adding enrollment with:");
   fp_dbg("\ttemplate ID:");
   fp_dbg_large_hex(enrollment->template_id, DB2_ID_SIZE);
   fp_dbg("\tuser ID:");
   fp_dbg_large_hex(enrollment->user_id, sizeof(user_id_t));
   fp_dbg("\tfinger ID: %u", enrollment->finger_id);

   BOOL_CHECK(serialize_container(container, container_cnt, serialized,
                                  serialized_size));

   fp_dbg("serialized container:");
   fp_dbg_large_hex(*serialized, *serialized_size);

error:
   return ret;
}

/* ========================================================================= */

/* Async cmd send ========================================================== */

typedef enum {
   CMD_STATE_SEND,
   CMD_STATE_GET_RESP,
   CMD_NUM_STATES,
} cmd_state_t;

static void cmd_receive_cb(FpiUsbTransfer *transfer, FpDevice *device,
                           gpointer user_data, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   cmd_ssm_data_t *ssm_data = (cmd_ssm_data_t *)user_data;
   const int status_header_len = 2;

   if (error != NULL) {
      /* NOTE: assumes timeout should never happen for receiving. */
      goto error;
   }

   /* some debug output */
   fp_dbg("  Transfer: length: %lu, actual_length: %lu", transfer->length,
          transfer->actual_length);
   fp_dbg("  raw wrapped resp:");
   fp_dbg_large_hex(transfer->buffer, transfer->actual_length);

   /* Unwrap command if in TLS session */
   if (self->tls.established && transfer->actual_length != status_header_len) {
      tls_unwrap(self, transfer->buffer, transfer->actual_length,
                 &ssm_data->recv_data, &ssm_data->recv_size, &error);
      if (error != NULL) {
         goto error;
      }
   } else {
      /* Response can be shorter, e.g. on error */
      ssm_data->recv_size = transfer->actual_length;
      ssm_data->recv_data = g_malloc(ssm_data->recv_size);
      memcpy(ssm_data->recv_data, transfer->buffer, transfer->actual_length);
   }

#ifdef COMMUNICATION_DEBUG
   fp_dbg("  raw unwrapped resp:");
   fp_dbg_large_hex(ssm_data->recv_data, ssm_data->recv_size);
   fp_dbg("<--- 0x%x = %s", ssm_data->cmd_id, cmd_id_to_str(ssm_data->cmd_id));
#endif

   /* stauts is not initialized to 0 as 0 marks success */
   guint16 status = 0xffff;
   status = FP_READ_UINT16_LE(ssm_data->recv_data);
   if ((ssm_data->check_status) && !sensor_status_is_result_ok(status)) {
      fpi_ssm_mark_failed(
          transfer->ssm,
          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                               "Device responded with status: 0x%04x aka %s",
                               status, sensor_status_to_string(status)));
      return;
   }

   if (error != NULL) {
      g_free(ssm_data->recv_data);
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      (ssm_data->callback)(self, ssm_data->recv_data, ssm_data->recv_size,
                           NULL);
   }
   fpi_ssm_mark_completed(transfer->ssm);
   return;
error:
   fpi_ssm_mark_failed(transfer->ssm, error);
}

static void cmd_state_send(FpiDeviceSynaTudorMoc *self,
                           cmd_ssm_data_t *ssm_data)
{
   g_autofree guint8 *wrapped_data = NULL;
   gsize wrapped_size = 0;

#ifdef COMMUNICATION_DEBUG
   /* some debug info */
   fp_dbg("---> 0x%x = %s", ssm_data->cmd_id, cmd_id_to_str(ssm_data->cmd_id));
   fp_dbg("  expected recv size: %lu", ssm_data->expected_recv_size);
   fp_dbg("  raw unwrapped req:");
   fp_dbg_large_hex(ssm_data->send_data, ssm_data->send_size);
#endif

   /* Wrap command if in TLS session */
   if (self->tls.established) {
      GError *error = NULL;
      if (!tls_wrap(self, ssm_data->send_data, ssm_data->send_size,
                    &wrapped_data, &wrapped_size, &error)) {
         fpi_ssm_mark_failed(self->cmd_ssm, error);
         return;
      } else {
         g_free(ssm_data->send_data);
      }
      /* TLS response is expected to be larger */
      ssm_data->expected_recv_size += WRAP_RESPONSE_ADDITIONAL_SIZE;
   } else {
      wrapped_data = ssm_data->send_data;
      wrapped_size = ssm_data->send_size;
   }

#ifdef COMMUNICATION_DEBUG
   fp_dbg("  raw wrapped req:");
   fp_dbg_large_hex(wrapped_data, wrapped_size);
#endif

   /* Send out the command */
   g_assert(self->cmd_transfer == NULL);
   self->cmd_transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   self->cmd_transfer->short_is_error = FALSE;
   fpi_usb_transfer_fill_bulk(self->cmd_transfer, USB_EP_REQUEST, wrapped_size);
   memcpy(self->cmd_transfer->buffer, wrapped_data, wrapped_size);

   self->cmd_transfer->ssm = self->cmd_ssm;
   fpi_usb_transfer_submit(self->cmd_transfer, USB_TRANSFER_TIMEOUT_MS, NULL,
                           fpi_ssm_usb_transfer_cb, NULL);
   self->cmd_transfer = NULL;
}

static void cmd_run_state(FpiSsm *ssm, FpDevice *dev)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(dev);
   cmd_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   switch (fpi_ssm_get_cur_state(ssm)) {
   case CMD_STATE_SEND:
      cmd_state_send(self, ssm_data);
      break;

   case CMD_STATE_GET_RESP:
      self->cmd_transfer = fpi_usb_transfer_new(dev);
      self->cmd_transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk(self->cmd_transfer, USB_EP_REPLY,
                                 ssm_data->expected_recv_size);
      fpi_usb_transfer_submit(self->cmd_transfer, USB_TRANSFER_TIMEOUT_MS, NULL,
                              cmd_receive_cb, fpi_ssm_get_data(ssm));
      self->cmd_transfer = NULL;
      break;
   }
}

static void cmd_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(dev);

   if (error != NULL) {
      FP_ERR_FANCY("Cmd transfer resulted in error: %s", error->message);
      fpi_ssm_mark_failed(self->task_ssm, error);
      return;
   }

   self->cmd_ssm = NULL;
   fpi_device_critical_leave(dev);
}

void synaptics_secure_connect(FpiDeviceSynaTudorMoc *self, guint8 *send_data,
                              const gsize send_size,
                              const gsize expected_recv_size,
                              const gboolean check_status,
                              const CmdCallback callback)
{
   /* Start of a new command, create the state machine. */
   g_assert(callback != NULL);
   g_assert(expected_recv_size > 0);
   g_assert(self->cmd_transfer == NULL);

   self->cmd_ssm = fpi_ssm_new_full(FP_DEVICE(self), cmd_run_state,
                                    CMD_NUM_STATES, CMD_NUM_STATES, "Cmd");

   cmd_ssm_data_t *data = g_new0(cmd_ssm_data_t, 1);
   data->send_data = send_data;
   data->send_size = send_size;
   data->expected_recv_size = expected_recv_size;
   data->callback = callback;
   data->check_status = check_status;
   data->cmd_id = send_data[0];
   fpi_ssm_set_data(self->cmd_ssm, data, g_free);

   fpi_device_critical_enter(FP_DEVICE(self));
   fpi_ssm_start(self->cmd_ssm, cmd_ssm_done);
}

static void recv_no_operation(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                              gsize recv_size, GError *error)
{

   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* VCSFW_CMD_GET_VERSION async ============================================= */

static gboolean parse_get_version(FpiByteReader *reader, mis_version_t *result)
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

static void fp_dbg_get_version(mis_version_t *get_version)
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

static void recv_get_version(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                             gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   read_ok &= parse_get_version(&reader, &self->mis_version);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   fp_dbg_get_version(&self->mis_version);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* Sends a VCSFW_CMD_GET_VERSION command and stores result to self */
void send_get_version(FpiDeviceSynaTudorMoc *self)
{
   const guint send_size = 1;
   const guint expected_recv_size = 38;
   guint8 *send_data = g_malloc(send_size);
   send_data[0] = VCSFW_CMD_GET_VERSION;

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_get_version);
}

/* VCSFW_CMD_SEND_FRAME_ACQ async=========================================== */

static void recv_frame_acq(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                           gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   gboolean read_ok = TRUE;
   guint16 status;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   status = FP_READ_UINT16_LE(recv_data);
   if (status == RESPONSE_PROCESSING_FRAME) {
      fp_dbg("received status RESPONSE_PROCESSING_FRAME, retrying");
      if (self->frame_acq_config.retries_left <= 0) {
         error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                      "no retries left for frame acq");
         return;
      } else {
         self->frame_acq_config.retries_left -= 1;
         send_frame_acq(self, self->frame_acq_config.last_capture_flags);
         return;
      }
   } else if (!sensor_status_is_result_ok(status)) {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "Received status 0x%04x aka %s", status,
                                   sensor_status_to_string(status));
      goto error;
   }

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_frame_acq(FpiDeviceSynaTudorMoc *self, capture_flags_t capture_flags)
{
   const guint send_size = 17;
   const guint expected_recv_size = 2;

   const guint32 num_frames = 1;
   // TODO: consider a better place for init
   self->frame_acq_config.num_retries = 3;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, FALSE);

   gboolean written = TRUE;
   /* As there were only two capture flags used, I simplified the request logic
    * a bit */
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_FRAME_ACQ); // +0
   /* I was unable to find the meaning of these values, so I did not abstract
    * them into constants */
   if (capture_flags == CAPTURE_FLAGS_AUTH) {
      written &= fpi_byte_writer_put_uint32_le(&writer, 4116); // +1
   } else { // CAPTURE_FLAGS_ENROLL
      written &= fpi_byte_writer_put_uint32_le(&writer, 12); // +1
   }
   written &= fpi_byte_writer_put_uint32_le(&writer, num_frames); // +5
   written &= fpi_byte_writer_put_uint16_le(&writer, 1);          // +9
   written &= fpi_byte_writer_put_uint8(&writer, 0);              // +11
   written &= fpi_byte_writer_put_uint8(&writer, 8);              // +13
   written &= fpi_byte_writer_put_uint8(&writer, 1);              // +14
   written &= fpi_byte_writer_put_uint8(&writer, 1);              // +15
   written &= fpi_byte_writer_put_uint8(&writer, 1);              // +16
   written &= fpi_byte_writer_put_uint8(&writer, 0);              // +17
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   self->frame_acq_config.last_capture_flags = capture_flags;

   /* Do not check the response status as there is a status on which we
    * should send the command again */
   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            FALSE, recv_frame_acq);
}
/* VCSFW_CMD_FRAME_FINISH async============================================= */

void send_frame_finish(FpiDeviceSynaTudorMoc *self)
{

   const guint send_size = 1;
   const guint expected_recv_size = 2;
   guint8 *send_data = g_malloc(send_size);
   send_data[0] = VCSFW_CMD_FRAME_FINISH;
   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_no_operation);
}

/* VCSFW_CMD_ENROLL async ================================================== */

void send_enroll_start(FpiDeviceSynaTudorMoc *self)
{
   /* Unused parameters of original function*/
   const gsize nonce_buffer_size = 0;

   const guint send_size = 13;
   const guint expected_recv_size = 6 + nonce_buffer_size;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);        // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_START); // +1
   /* deduced name */
   const guint32 send_nonce_buffer = nonce_buffer_size != 0;
   written &= fpi_byte_writer_put_uint32_le(&writer, send_nonce_buffer); // +5
   written &= fpi_byte_writer_put_uint32_le(&writer, nonce_buffer_size); // +9
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   /* no need to receive nonce buffer as it it not used here */
   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_no_operation);
}

static gboolean parse_enroll_stats(FpiByteReader *reader,
                                   enroll_stats_t *result)
{
   gboolean read_ok = TRUE;

   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(reader, 2);
   read_ok &= fpi_byte_reader_get_uint16_le(reader, &result->progress);
   /* the template id is read beforehand, so do not read it again */
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

static void recv_enroll_add_image(FpiDeviceSynaTudorMoc *self,
                                  guint8 *recv_data, gsize recv_size,
                                  GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   enroll_stats_t *enroll_stats = &self->parsed_recv_data.enroll_stats;

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   const guint8 *template_id_offset = NULL;
   guint32 enroll_stat_buffer_size;
   read_ok &=
       fpi_byte_reader_get_data(&reader, DB2_ID_SIZE, &template_id_offset);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &enroll_stat_buffer_size);
   if (read_ok && enroll_stat_buffer_size != 60) {
      error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "qm struct size mismatch - expected: %u, got: %u", 60,
          enroll_stat_buffer_size);
      goto error;
   }
   read_ok &= parse_enroll_stats(&reader, enroll_stats);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   fp_dbg_enroll_stats(enroll_stats);

   /* template_id is only given when progress is 100% */
   if (enroll_stats->progress == 100) {
      memcpy(enroll_stats->template_id, template_id_offset,
             sizeof(enroll_stats->template_id));

      fp_dbg("\tenroll template_id:");
      fp_dbg_large_hex(enroll_stats->template_id, DB2_ID_SIZE);
   }

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_enroll_add_image(FpiDeviceSynaTudorMoc *self)
{
   const guint send_size = 5;
   const guint expected_recv_size = 82;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL); // +0
   written &=
       fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_ADD_IMAGE); // +1
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_enroll_add_image);
}

void send_enroll_commit(FpiDeviceSynaTudorMoc *self, guint8 *enroll_commit_data,
                        gsize enroll_commit_data_size)
{
   const guint send_size = 13 + enroll_commit_data_size;
   const guint expected_recv_size = 2;
   g_assert((enroll_commit_data_size != 0) && (enroll_commit_data != NULL));

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL); // +0
   written &=
       fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_COMMIT); // +1
   written &= fpi_byte_writer_put_uint32_le(&writer, 0);             // =5
   written &=
       fpi_byte_writer_put_uint32_le(&writer, enroll_commit_data_size); // +9
   written &= fpi_byte_writer_put_data(&writer, enroll_commit_data,
                                       enroll_commit_data_size); // +13
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_no_operation);
}

void send_enroll_finish(FpiDeviceSynaTudorMoc *self)
{
   const guint send_size = 5;
   const guint expected_recv_size = 2;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL); // +0
   written &=
       fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_FINISH); // +1
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_no_operation);
}

/* VCSFW_CMD_IDENTIFY_MATCH async ========================================== */

static void recv_identify_match(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                                gsize recv_size, GError *error)
{
   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
      return;
   }
   g_assert(recv_data != NULL);

   match_result_t *match_result = &self->parsed_recv_data.match_result;

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   guint16 status = 0;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   /* VCS_RESULT_MATCHER_MATCH_FAILED given on identifiy fail
    * VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 given on verify fail */
   if (status == VCS_RESULT_MATCHER_MATCH_FAILED ||
       status == VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2) {
      fp_dbg("Received status 0x%04x aka match fail", status);
      match_result->matched = FALSE;
      goto error;
   } else if (!sensor_status_is_result_ok(status)) {
      error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO, "%s received error status: 0x%04x aka %s",
          __FUNCTION__, status, sensor_status_to_string(status));
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
   const guint8 *z_data;
   read_ok &= fpi_byte_reader_get_data(&reader, z_len, &z_data);

   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   if (y_len != 0 || z_len == 0) {
      error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "received unimplemented identify message with y_len=%d, z_len=%d",
          y_len, z_len);
      goto error;
   }

   if (match_stats_len != MATCH_STATS_SIZE) {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "qm struct size mismatch!");
      goto error;
   }

   match_result->matched = TRUE;

   if (!get_enrollment_data_from_serialized_container(
           z_data, z_len, &match_result->matched_enrollment, &error)) {
      goto error;
   }

   fp_dbg("Match identified with enrollment:");
   fp_dbg_enrollment(&match_result->matched_enrollment);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_identify_match(FpiDeviceSynaTudorMoc *self,
                         db2_id_t *template_ids_to_match,
                         gsize template_ids_cnt)
{
   /* we will get operation denier error if TLS is not established */
   g_assert(self->tls.established);

   /* unused argument */
   const gsize data_2_size = 0;
   const guint8 *data_2 = NULL;

   /* send only one type of data */
   g_assert(((data_2_size == 0) && (data_2 == NULL)) ||
            ((template_ids_cnt == 0) && (template_ids_to_match == 0)));

   const gsize template_id_array_size =
       sizeof(*template_ids_to_match) * template_ids_cnt;

   const guint send_size = 13 + data_2_size + template_id_array_size;
   const guint expected_recv_size = 1602;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &=
       fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_IDENTIFY_MATCH); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer,
                                            VCSFW_CMD_IDENTIFY_WBF_MATCH); // +1
   written &=
       fpi_byte_writer_put_uint32_le(&writer, template_id_array_size); // +5
   written &= fpi_byte_writer_put_uint32_le(&writer, data_2_size);     // +9
   if (template_ids_to_match != NULL) {
      fpi_byte_writer_put_data(&writer, *template_ids_to_match,
                               template_ids_cnt *
                                   template_id_array_size); // +13
   } else if (data_2 != NULL) {
      fpi_byte_writer_put_data(&writer, data_2, data_2_size); // +13
   }
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            FALSE, recv_identify_match);
}

/* VCSFW_CMD_GET_IMAGE_METRICS async ======================================= */

static void recv_get_image_metrics(FpiDeviceSynaTudorMoc *self,
                                   guint8 *recv_data, gsize recv_size,
                                   GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   if (recv_size < 3) {
      error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Requested image metrics were unsupported by sensor");
      goto error;
   }

   img_metrics_t *img_metrics = &self->parsed_recv_data.img_metrics;

   FpiByteReader reader;
   gboolean read_ok = TRUE;
   guint32 recv_data_size = 0;

   fpi_byte_reader_init(&reader, recv_data, recv_size);
   /* we do not need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &img_metrics->type);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &recv_data_size);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   if (recv_data_size == 0) {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "Unable to query img metrics now");
      goto error;
   } else if (img_metrics->type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE &&
              recv_data_size ==
                  MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE_DATA_SIZE) {

      /* read IPL finger coverage */
      read_ok &= fpi_byte_reader_get_uint32_le(
          &reader, &img_metrics->data.ipl_finger_coverage.ipl_finger_coverage);
      READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);
      fp_dbg("Image finger IPL coverage is %u of sensor",
             img_metrics->data.ipl_finger_coverage.ipl_finger_coverage);
   } else if (img_metrics->type == MIS_IMAGE_METRICS_IMG_QUALITY &&
              recv_data_size == MIS_IMAGE_METRICS_IMG_QUALITY_DATA_SIZE) {
      /* read image quality coverage */
      read_ok &= fpi_byte_reader_get_uint32_le(
          &reader, &img_metrics->data.matcher_stats.img_quality);
      read_ok &= fpi_byte_reader_get_uint32_le(
          &reader, &img_metrics->data.matcher_stats.sensor_coverage);
      READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);
      /* not reading the other 4 bytes as the interpretation is unknown */
      fp_dbg("Matcher:");
      fp_dbg("\tImage finger quality is %u%%",
             img_metrics->data.matcher_stats.img_quality);
      fp_dbg("\tSensor coverage is %u%%",
             img_metrics->data.matcher_stats.sensor_coverage);
   } else {
      error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Requested metrics were not supported; got %u bytes as data size",
          recv_data_size);
      goto error;
   }

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_get_image_metrics(FpiDeviceSynaTudorMoc *self,
                            img_metrics_type_t type)
{
   const guint send_size = 5;
   guint expected_recv_size = 10;

   if (type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE) {
      expected_recv_size = 14;
   } else if (type == MIS_IMAGE_METRICS_IMG_QUALITY) {
      expected_recv_size = 70;
   }

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &=
       fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_GET_IMAGE_METRICS); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer,
                                            type); // +1
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_get_image_metrics);
}

/* VCSFW_CMD_EVENT_CONFIG ================================================== */

static void recv_event_config(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                              gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   if (recv_size < 66) {
      error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO,
          "Transfer in version response to version query was too short");
      goto error;
   }

   self->events.seq_num = FP_READ_UINT16_LE(&recv_data[64]);
   fp_dbg("Current event sequence number is %d", self->events.seq_num);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_event_config(FpiDeviceSynaTudorMoc *self, guint32 event_mask)
{
   const gint event_mask_cnt = 8;
   fp_dbg("Setting event mask to: 0b%b", event_mask);

   const guint send_size = 37;
   const guint expected_recv_size = 66;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_EVENT_CONFIG);
   /* repeat event mask 8 times */
   for (gint i = 0; i < event_mask_cnt; ++i) {
      written &= fpi_byte_writer_put_uint32_le(&writer, event_mask);
   }
   if (event_mask == 0) {
      written &= fpi_byte_writer_put_uint32_le(&writer, 4);
   } else {
      written &= fpi_byte_writer_put_uint32_le(&writer, 0);
   }
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);
   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_event_config);
}

/* VCSFW_CMD_EVENT_READ ==================================================== */

static void recv_event_read(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                            gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   guint16 status = 0;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   if (!sensor_status_is_result_ok(status)) {
      if (sensor_status_is_result_bad_param(status) &&
          !self->events.read_in_legacy_mode) {
         fp_dbg("Received status 0x%04x on event read, falling back to "
                "legacy event reading -> sending event read again",
                status);
         self->events.read_in_legacy_mode = TRUE;
         send_event_read(self);
         return;
      } else {
         error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                      "received status: 0x%04x", status);
         goto error;
      }
   }

   guint16 recv_num_events = 0;
   guint16 recv_num_pending_events = 0;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_events);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_pending_events);
   fp_dbg("Received num_events: %d, num_pending_events: %d", recv_num_events,
          recv_num_pending_events);

   /* read event types */
   self->parsed_recv_data.read_event_mask = 0;
   for (int i = 0; i < recv_num_events && read_ok; ++i) {
      guint8 event;
      read_ok &= fpi_byte_reader_get_uint8(&reader, &event);
      if (read_ok) {
         self->parsed_recv_data.read_event_mask |= 1 << event;
      }
      /* skip over unknown stuff */
      read_ok &= fpi_byte_reader_skip(&reader, 11);
   }
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

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

   if (self->events.num_pending > 0) {
      fp_dbg("There are %u events pending -> sending event read again",
             self->events.num_pending);
      send_event_read(self);
      return;
   }

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_event_read(FpiDeviceSynaTudorMoc *self)
{
   const guint16 max_num_events_in_resp = 32;

   const guint send_size = self->events.read_in_legacy_mode ? 5 : 9;
   const guint expected_recv_size = 6 + 12 * max_num_events_in_resp;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_EVENT_READ);       // +0
   fpi_byte_writer_put_uint16_le(&writer, self->events.seq_num);   // +1
   fpi_byte_writer_put_uint16_le(&writer, max_num_events_in_resp); // +3
   if (!self->events.read_in_legacy_mode) {
      fpi_byte_writer_put_uint32_le(&writer, 1); // +5
   }
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);
   /* do not check status as some statuses indicate that legacy reading mode
    * should be used */
   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            FALSE, recv_event_read);
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

static void recv_db2_info(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                          gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   db2_info_t db2_info;
   read_ok &= parse_db2_info(&reader, &db2_info);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   fp_dbg_db2_info(&db2_info);

   self->storage.num_current_users = db2_info.num_current_users;
   self->storage.num_current_templates = db2_info.num_current_templates;
   self->storage.num_current_payloads = db2_info.num_current_payloads;

   self->parsed_recv_data.cleanup_required =
       db2_info.num_deleted_users != 0 &&
       db2_info.num_available_user_slots == 0;

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* prints DB2 info on debug output and stores numbers of current users,
 * templates and payloads */
void send_db2_info(FpiDeviceSynaTudorMoc *self)
{
   const guint send_size = 2;
   const guint expected_recv_size = 64;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &=
       fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_GET_DB_INFO); // +0
   written &= fpi_byte_writer_put_uint8(&writer, 1);                  // +1
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_info);
}

/* VCSFW_CMD_DB2_FORMAT ==================================================== */

static void recv_db2_format(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                            gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   /* skip over unknown4 */
   read_ok &= fpi_byte_reader_skip(&reader, 4);
   guint new_partition_version = 0;
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &new_partition_version);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   fp_dbg("Format succeeded with new partition version: %d",
          new_partition_version);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* prints DB2 info on debug output and stores numbers of current users,
 * templates and payloads */
void send_db2_format(FpiDeviceSynaTudorMoc *self)
{
   const guint send_size = 12;
   const guint expected_recv_size = 8;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_FORMAT); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, 1);                // +1
   written &= fpi_byte_writer_fill(&writer, 0, send_size - 2);
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_format);
}

/* VCSFW_CMD_DB2_CLEANUP =================================================== */

static void recv_db2_cleanup(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                             gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   guint16 num_erased_slots = 0;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_erased_slots);
   guint32 new_partition_version = 0;
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &new_partition_version);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   fp_dbg("DB2 cleanup succeeded with:");
   fp_dbg("\tNumber of erased slots: %u", num_erased_slots);
   fp_dbg("\tNew partition version: %u", new_partition_version);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* prints DB2 info on debug output and stores numbers of current users,
 * templates and payloads */
void send_db2_cleanup(FpiDeviceSynaTudorMoc *self)
{
   const guint8 unused_param = 1;

   const guint send_size = 2;
   const guint expected_recv_size = 8;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_CLEANUP); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, unused_param);      // +1
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_cleanup);
}

/* VCSFW_CMD_DB2_DELETE_OBJECT async ======================================= */

static void recv_db2_delete_object(FpiDeviceSynaTudorMoc *self,
                                   guint8 *recv_data, gsize recv_size,
                                   GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 num_deleted_objects = 0;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_deleted_objects);

   if (!read_ok) {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "Transfer in response to version DB2 delete "
                                   "object was too short");
      goto error;
   }
   fp_dbg("Delete object succeeded with number of deleted objects: %d",
          num_deleted_objects);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_db2_delete_object(FpiDeviceSynaTudorMoc *self,
                            const obj_type_t obj_type, const db2_id_t obj_id)
{
   const guint send_size = 21;
   const guint expected_recv_size = 4;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &=
       fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_DELETE_OBJECT); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, obj_type);         // +1
   written &= fpi_byte_writer_put_data(&writer, (guint8 *)obj_id,
                                       DB2_ID_SIZE); // +5
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   fp_dbg("Sending delete object of type: %d with ID:", obj_type);
   fp_dbg_large_hex((guint8 *)obj_id, DB2_ID_SIZE);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_delete_object);
}

/* VCSFW_CMD_GET_OBJECT_LIST async =========================================
 */

static void fp_dbg_object_list(db2_obj_list_t *obj_list)
{
   for (gint i = 0; i < obj_list->len; ++i) {
      fp_dbg("\tat position %d is:", i);
      fp_dbg_large_hex((obj_list->obj_list)[i], DB2_ID_SIZE);
   }
}

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

static void recv_db2_get_object_list(FpiDeviceSynaTudorMoc *self,
                                     guint8 *recv_data, gsize recv_size,
                                     GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   db2_obj_list_t *db2_obj_list = &self->parsed_recv_data.db2_obj_list;

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &db2_obj_list->len);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   fp_dbg("Requested object list has %d elements:", db2_obj_list->len);

   read_ok &= fpi_byte_reader_dup_data(&reader, db2_obj_list->len * DB2_ID_SIZE,
                                       (gpointer)&db2_obj_list->obj_list);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);
   fp_dbg_object_list(db2_obj_list);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* NOTE: the current number of items in db2 database needs to be up to date when
 * calling this function */
void send_db2_get_object_list(FpiDeviceSynaTudorMoc *self,
                              const obj_type_t obj_type, const db2_id_t obj_id)
{
   const guint send_size = 21;
   const guint expected_recv_size = get_object_list_recv_size(self, obj_type);

   fp_dbg("Requesting object list for object of type: %u and with id:",
          obj_type);
   fp_dbg_large_hex(obj_id, DB2_ID_SIZE);

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &=
       fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_GET_OBJECT_LIST); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, obj_type);           // +1
   written &= fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);     // +5
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_get_object_list);
}

/* VCSFW_CMD_DB2_GET_OBJECT_INFO async ===================================== */

/* NOTE: saves raw data to self which require freeing */
static void recv_db2_get_object_info(FpiDeviceSynaTudorMoc *self,
                                     guint8 *recv_data, gsize recv_size,
                                     GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   raw_resp_t *raw_resp = &self->parsed_recv_data.raw_resp;

   fp_dbg("Received object info:");
   fp_dbg_large_hex(recv_data, recv_size);

   raw_resp->data = recv_data;
   raw_resp->size = recv_size;

error:
   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
      g_free(recv_data);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_db2_get_object_info(FpiDeviceSynaTudorMoc *self,
                              const obj_type_t obj_type, const db2_id_t obj_id)
{
   const guint send_size = 21;
   const guint expected_recv_size = obj_type == OBJ_TYPE_USERS ? 12 : 52;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer,
                                        VCSFW_CMD_DB2_GET_OBJECT_INFO); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, obj_type);         // +1
   written &= fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);   // +5
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   fp_dbg("Getting object info for object of type: %u with id:", obj_type);
   fp_dbg_large_hex(obj_id, DB2_ID_SIZE);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_get_object_info);
}

/* VCSFW_CMD_GET_OBJECT_DATA =============================================== */

static void recv_db2_get_object_data(FpiDeviceSynaTudorMoc *self,
                                     guint8 *recv_data, gsize recv_size,
                                     GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   db2_obj_data_t *obj_data = &self->parsed_recv_data.db2_obj_data;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   /* skip over unknown */
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &obj_data->size);
   fp_dbg("Received object data of length %u", obj_data->size);
   read_ok &=
       fpi_byte_reader_dup_data(&reader, obj_data->size, &obj_data->data);

   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_db2_get_object_data(FpiDeviceSynaTudorMoc *self,
                              const obj_type_t obj_type, const db2_id_t obj_id,
                              gsize obj_data_size)
{
   g_assert(obj_data_size < 65535);

   const guint send_size = 21;
   guint expected_recv_size = 0;

   if (obj_type == OBJ_TYPE_USERS) {
      expected_recv_size = 8;
      fp_warn("db2 get object data is untested for OBJ_TYPE_USERS");
   } else {
      expected_recv_size = 8 + obj_data_size;
   }

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer,
                                        VCSFW_CMD_DB2_GET_OBJECT_DATA); // +0
   written &= fpi_byte_writer_put_uint32_le(&writer, obj_type);         // +1
   written &= fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);   // +5
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_db2_get_object_data);
}

/* VCSFW_CMD_PAIR async ====================================================
 */

static void recv_pair(FpiDeviceSynaTudorMoc *self, guint8 *recv_data,
                      gsize recv_size, GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   /* no need to read status again */
   read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
   const guint8 *recv_host_cert_bytes = NULL;
   read_ok &= fpi_byte_reader_get_data(&reader, CERTIFICATE_SIZE,
                                       &recv_host_cert_bytes);
   const guint8 *sensor_cert_bytes = NULL;
   read_ok &=
       fpi_byte_reader_get_data(&reader, CERTIFICATE_SIZE, &sensor_cert_bytes);
   READ_OK_CHECK_ASYNC(self->task_ssm, read_ok);

   if (!parse_certificate(recv_host_cert_bytes, CERTIFICATE_SIZE,
                          &self->pairing_data.host_cert)) {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "Unable to parse host certifiacte");
      goto error;
   }
   if (!parse_certificate(sensor_cert_bytes, CERTIFICATE_SIZE,
                          &self->pairing_data.sensor_cert)) {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "Unable to parse sensor certifiacte");
      goto error;
   }

   if (self->pairing_data.private_key_initialized) {
      self->pairing_data.present = TRUE;
   } else {
      error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Private key is not initialized when it should be");
      goto error;
   }

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

void send_pair(FpiDeviceSynaTudorMoc *self, const guint8 *send_host_cert_bytes)
{
   g_assert(send_host_cert_bytes != NULL);

   const guint send_size = 1 + CERTIFICATE_SIZE;
   const guint expected_recv_size =
       SENSOR_FW_REPLY_STATUS_HEADER_LEN + 2 * CERTIFICATE_SIZE;

   FpiByteWriter writer;
   fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

   gboolean written = TRUE;
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_PAIR); // +0
   written &= fpi_byte_writer_put_data(&writer, send_host_cert_bytes,
                                       CERTIFICATE_SIZE); // +1
   CHECK_WRITER(self, self->task_ssm, &writer, written);

   guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            TRUE, recv_pair);
}

/* Wait for eevnts interrupt =============================================== */

static void recv_interrupt_wait_for_events(FpiUsbTransfer *transfer,
                                           FpDevice *device, gpointer user_data,
                                           GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   const guint smallest_expected_resp_len = 7;
   self->cmd_transfer = NULL;

   if (error != NULL) {
      FP_ERR_FANCY("Error in fpi_usb_transfer_submit: %s", error->message);
      goto error;
   }

   fp_dbg("recv_wait_for_events_interrupt");
   fp_dbg("\traw resp:");
   fp_dbg_large_hex(transfer->buffer, transfer->actual_length);

   guint16 sensor_event_seq_num = FP_READ_UINT16_LE(&transfer->buffer[6]);
   sensor_event_seq_num &= 0x1f;
   fp_dbg("\tEvent sequence numbers - host: %u, sensor: %u",
          self->events.seq_num, sensor_event_seq_num);

   if (transfer->actual_length > EVENT_BUFFER_SIZE ||
       transfer->actual_length < smallest_expected_resp_len) {
      fp_warn("Unexpected length of response in %s, got: %lu, expected: %d "
              "received array: ",
              __func__, transfer->actual_length, EVENT_BUFFER_SIZE);
      fp_dbg_large_hex(transfer->buffer, transfer->actual_length);
   }

   if (sensor_event_seq_num != self->events.seq_num) {
      memcpy(self->parsed_recv_data.event_buffer, transfer->buffer,
             transfer->actual_length);

      fpi_ssm_next_state(self->task_ssm);
   } else {
      send_interrupt_wait_for_events(self);
   }

   return;

error:
   fpi_ssm_mark_failed(self->task_ssm, error);
}

void send_interrupt_wait_for_events(FpiDeviceSynaTudorMoc *self)
{
   const guint8 recv_size = 7;
   g_assert(EVENT_BUFFER_SIZE >= recv_size);

   fp_info("Waiting for sensor to have events");

   /* receive data */
   g_assert(self->cmd_transfer == NULL);
   self->cmd_transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   self->cmd_transfer->short_is_error = FALSE;
   fpi_usb_transfer_fill_bulk(self->cmd_transfer, USB_EP_INTERRUPT,
                              EVENT_BUFFER_SIZE);
   fpi_usb_transfer_submit(self->cmd_transfer, USB_INTERRUPT_TIMEOUT_MS,
                           self->interrupt_cancellable,
                           recv_interrupt_wait_for_events, NULL);
}

/* ========================================================================= */

static void recv_get_version_tls_force_close(FpiDeviceSynaTudorMoc *self,
                                             guint8 *recv_data, gsize recv_size,
                                             GError *error)
{
   if (error != NULL) {
      goto error;
   }
   g_assert(recv_data != NULL);

   /* deduced name */
   const guint16 unclosed_tls_session_status = 0x315;

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   if (recv_size < 2) {
      error =
          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                               "Response to get_version command was too short");
      goto error;
   }

   guint16 status = FP_READ_UINT16_LE(recv_data);
   if (sensor_status_is_result_ok(status)) {
      fp_dbg("TLS force close - sensor was not in TLS session");
   } else if (status == unclosed_tls_session_status) {
      fp_dbg("TLS force close - sensor was in TLS status");
   } else {
      error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                   "Device responded with error: 0x%04x aka %s",
                                   status, sensor_status_to_string(status));
   }

error:
   g_free(recv_data);

   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   } else {
      fpi_ssm_next_state(self->task_ssm);
   }
}

/* Sends a get_version command to force the sensor to close its TLS
 session
 * -> error 0x315 is expected (its real name is not known) */
void send_cmd_to_force_close_sensor_tls_session(FpiDeviceSynaTudorMoc *self)
{
   const guint send_size = 1;
   /* we may get a TLS alert message, so increase the recv_size accordingly */
   const guint expected_recv_size = 38 + WRAP_RESPONSE_ADDITIONAL_SIZE;
   guint8 *send_data = g_malloc(send_size);
   send_data[0] = VCSFW_CMD_GET_VERSION;

   synaptics_secure_connect(self, send_data, send_size, expected_recv_size,
                            FALSE, recv_get_version_tls_force_close);
}

/* Bootloader functions ==================================================== */

static void write_dft(FpiDeviceSynaTudorMoc *self, const guint8 *data,
                      const gsize data_size, FpiUsbTransferCallback callback)
{
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

   fpi_usb_transfer_submit(transfer, USB_TRANSFER_TIMEOUT_MS, NULL, callback,
                           NULL);
}

gboolean sensor_is_in_bootloader_mode(FpiDeviceSynaTudorMoc *self)
{
   return self->mis_version.product_id == PRODUCT_ID_BOOTLOADER_1 ||
          self->mis_version.product_id == PRODUCT_ID_BOOTLOADER_2;
}

static void reset_usb_device_on_callback(FpiUsbTransfer *transfer,
                                         FpDevice *device, gpointer user_data,
                                         GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   if (error != NULL) {
      goto error;
   }

   g_usb_device_reset(fpi_device_get_usb_device(device), &error);
   if (error != NULL) {
      goto error;
   }

   fpi_ssm_next_state(self->task_ssm);
   return;

error:
   fpi_ssm_mark_failed(self->task_ssm, error);
}

/**
 * Sends a command to enter/exit bootloader mode
 *
 * @param enter TRUE to enter BL mode, FALSE to exit
 */
void send_bootloader_mode_enter_exit(FpiDeviceSynaTudorMoc *self,
                                     gboolean enter)
{

   const guint8 to_send_exit[8] = {0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00};
   const guint8 to_send_enter[8] = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x01, 0x00};
   const guint8 *to_send = NULL;

   if (enter) {
      fp_dbg("Entering bootloader mode");
      to_send = to_send_enter;

   } else {
      fp_dbg("Exiting bootloader mode");
      to_send = to_send_exit;
   }

   write_dft(self, to_send, 8, reset_usb_device_on_callback);
}
