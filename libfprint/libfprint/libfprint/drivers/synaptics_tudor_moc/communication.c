#include "communication.h"
#include "container.c"
#include "drivers_api.h"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-usb-transfer.h"
#include "other_constants.h"
#include "tls.h"
#include "utils.h"
#include <glib.h>
#include <stdio.h>

static const char *convert_sensor_status_to_string(guint16 status)
{
   const char *ret;

   switch (status) {
   case 0x000:
      ret = "RESPONSE_OK_1";
      break;
   case 0x401:
      ret = "VCS_RESULT_SENSOR_BAD_CMD";
      break;
   case 0x403:
      ret = "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_1";
      break;
   case 0x404:
      ret = "VCS_RESULT_GEN_OPERATION_DENIED";
      break;
   case 0x405:
      ret = "RESPONSE_BAD_PARAM_1";
      break;
   case 0x406:
      ret = "RESPONSE_BAD_PARAM_2";
      break;
   case 0x407:
      ret = "RESPONSE_BAD_PARAM_3";
      break;
   case 0x412:
      ret = "RESPONSE_OK_2";
      break;
   case 0x509:
      ret = "VCS_RESULT_MATCHER_MATCH_FAILED";
      break;
   case 0x5B6:
      ret = "VCS_RESULT_SENSOR_FRAME_NOT_READY";
      break;
   case 0x5CC:
      ret = "RESPONSE_OK_3";
      break;
   case 0x680:
      ret = "VCS_RESULT_DB_FULL";
      break;
   case 0x683:
      ret = "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2";
      break;
   case 0x6EA:
      ret = "RESPONSE_PROCESSING_FRAME";
      break;
   case 0x315:
      ret = "last TLS session not closed";
      break;
   default:
      ret = "UNKNOWN_STATUS";
   }

   return ret;
}

static const char *cmd_id_to_str(vcsfw_cmd_t cmd_id)
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
   // case 0x69:
   //    ret = "bootloader mode exit/enter";
   //    break;
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
   // case 0xa6:
   //    ret = "yet unnamed cmd";
   //    break;
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

static void debug_print_db2_info(db2_info_t *db2_info)
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
   fp_dbg("\tnum_available_template_slots: %d",
          db2_info->num_available_template_slots);
   fp_dbg("\tnum_current_payloads: %d", db2_info->num_current_payloads);
   fp_dbg("\tnum_deleted_payloads: %d", db2_info->num_deleted_payloads);
   fp_dbg("\tnum_available_payload_slots: %d",
          db2_info->num_available_payload_slots);
}

gboolean synaptics_secure_connect(FpiDeviceSynapticsMoc *self,
                                  guint8 *send_data, gsize send_len,
                                  guint8 **recv_data, gsize *recv_len,
                                  const gboolean check_status)
{
   gboolean ret = TRUE;
   g_autoptr(FpiUsbTransfer) transfer = NULL;
   GError *error = NULL;
   *recv_data = NULL;
   guint16 status = 0xffff;

   const int status_header_len = 2;

   fp_dbg("---> 0x%x = %s", send_data[0], cmd_id_to_str(send_data[0]));

   guint8 *wrapped_data = NULL;
   gsize wrapped_size = 0;

   // Wrap command if in TLS session
   if (self->tls.established) {
      BOOL_CHECK(
          tls_wrap(self, send_data, send_len, &wrapped_data, &wrapped_size));
      *recv_len += WRAP_RESPONSE_ADDITIONAL_SIZE;
   } else {
      wrapped_data = send_data;
      wrapped_size = send_len;
   }
   fp_dbg("raw req:");
   print_array(send_data, send_len);
   fp_dbg("raw wreq:");
   print_array(wrapped_data, wrapped_size);

   /* send data */
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk(transfer, USB_EP_REQUEST, wrapped_size);
   transfer->short_is_error = TRUE;
   memcpy(transfer->buffer, wrapped_data, wrapped_size);
   BOOL_CHECK(fpi_usb_transfer_submit_sync(
       transfer, USB_TRANSFER_WAIT_TIMEOUT_MS, &error));
   fpi_usb_transfer_unref(transfer);

   /* receive data */
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk(transfer, USB_EP_REPLY, *recv_len);
   BOOL_CHECK(fpi_usb_transfer_submit_sync(transfer, 1000, &error));

   if (transfer->actual_length < status_header_len) {
      g_warning("Response transfer was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      ret = FALSE;
      goto error;
   }

   fp_dbg("Transfer: len: %lu, actual_length: %lu", transfer->length,
          transfer->actual_length);
   fp_dbg("raw wresp:");
   print_array(transfer->buffer, transfer->actual_length);

   // Unwrap command if in TLS session
   if (self->tls.established && transfer->actual_length != status_header_len) {
      BOOL_CHECK(tls_unwrap(self, transfer->buffer, transfer->actual_length,
                            recv_data, recv_len));
      fp_dbg("unwrapped message data:");
      print_array(*recv_data, *recv_len);
   } else {
      /* response can be shorter, e.g. on error */
      *recv_len = transfer->actual_length;

      *recv_data = g_malloc((*recv_len) * sizeof(guint8));
      memcpy(*recv_data, transfer->buffer, transfer->actual_length);
   }

   fp_dbg("<--- 0x%x = %s", send_data[0], cmd_id_to_str(send_data[0]));

   status = FP_READ_UINT16_LE(*recv_data);

   if ((check_status) && (status != RESPONSE_OK_1) &&
       (status != RESPONSE_OK_2) && (status != RESPONSE_OK_3)) {
      g_warning("Device responded with error: 0x%04x aka %s", status,
                convert_sensor_status_to_string(status));
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      ret = FALSE;
      goto error;
   }

   fp_dbg("Unwrapped response data:");
   print_array(*recv_data, *recv_len);
error:
   // fpi_usb_transfer_unref(transfer);
   if (self->tls.established && wrapped_data != NULL) {
      g_free(wrapped_data);
   }
   if (!ret && *recv_data != NULL) {
      g_free(*recv_data);
      *recv_data = NULL;
   }
   return ret;
}

gboolean send_get_version(FpiDeviceSynapticsMoc *self, get_version_t *resp,
                          GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 1;
   gsize recv_size = 38;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_GET_VERSION;

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      ret = FALSE;
      goto error;
   }

   g_assert(recv_data != NULL);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 status;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->fw_build_num);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->fw_build_num);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->fw_version_major);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->fw_version_minor);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->fw_target);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->product_id);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->silicon_revision);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->formal_release);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->platform);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->patch);
   const guint8 *ser_num_data;
   if (fpi_byte_reader_get_data(&reader, sizeof(resp->serial_number),
                                &ser_num_data)) {

      memcpy(resp->serial_number, ser_num_data, sizeof(resp->serial_number));
   } else {
      read_ok = FALSE;
   }
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->security);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->interface);
   read_ok &= fpi_byte_reader_skip(&reader, 8);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->device_type);
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->provision_state);

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      ret = FALSE;
      goto error;
   }

   fp_dbg("Get version data:");
   fp_dbg("\tBuild Time: %d", resp->fw_build_time);
   fp_dbg("\tBuild Num: %d", resp->fw_build_num);
   fp_dbg("\tVersion: %d.%d", resp->fw_version_major, resp->fw_version_minor);
   fp_dbg("\tTarget: %d", resp->fw_target);
   fp_dbg("\tProduct: %c", resp->product_id);
   fp_dbg("\tSilicon revision: %d", resp->silicon_revision);
   fp_dbg("\tFormal release: %d", resp->formal_release);
   fp_dbg("\tPlatform: %d", resp->platform);
   fp_dbg("\tPatch: %d", resp->patch);
   fp_dbg("\tSecurity: %d", resp->security);
   fp_dbg("\tInterface: %d", resp->interface);
   fp_dbg("\tDevice type: %d", resp->device_type);
   fp_dbg("\tProvision state: %d", resp->provision_state);

error:
   return ret;
}

gboolean send_frame_acq(FpiDeviceSynapticsMoc *self, guint8 frame_flags,
                        GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 17;
   gsize recv_size = 2;

   const int no_retries = 3;

   /* These were the only frame flags used, which enabled a bit of
    * simplification.*/
   g_assert((frame_flags == CAPTURE_FLAGS_AUTH) ||
            (frame_flags == CAPTURE_FLAGS_ENROLL));

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_FRAME_ACQ;
   /*I was uable to find the meaning of these values, so I did not abstract
    * them into constants.*/
   if (frame_flags == CAPTURE_FLAGS_AUTH) {
      FP_WRITE_UINT32_LE(&(send_data[1]), 4116);
   } else {
      FP_WRITE_UINT32_LE(&(send_data[1]), 12);
   }
   FP_WRITE_UINT32_LE(&(send_data[5]), 1); // number of frames
   FP_WRITE_UINT16_LE(&(send_data[9]), 1);
   send_data[10] = 0;
   send_data[11] = 0;
   send_data[12] = 8;
   send_data[13] = 1;
   send_data[14] = 1;
   send_data[15] = 1;
   send_data[16] = 0;

   guint16 status;
   for (int i = 0; i < no_retries; ++i) {
      /*Do not check the response status as there is a status on which we
       * should send the command again*/
      BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size,
                                          &recv_data, &recv_size, FALSE));

      status = FP_READ_UINT16_LE(recv_data);
      if (status == RESPONSE_OK_1 || status == RESPONSE_OK_2 ||
          status == RESPONSE_OK_3) {
         break;
      } else if (status == RESPONSE_PROCESSING_FRAME) {
         fp_dbg("received status RESPONSE_PROCESSING_FRAME, retrying");
         continue;
      } else {
         fp_warn("Received status 0x%04x aka %s", status,
                 convert_sensor_status_to_string(status));
         goto error;
         ret = FALSE;
      }
   }

error:
   return ret;
}

gboolean send_frame_finish(FpiDeviceSynapticsMoc *self, GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 1;
   gsize recv_size = 2;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_FRAME_FINISH;

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

error:
   return ret;
}

gboolean send_enroll_start(FpiDeviceSynapticsMoc *self, GError *error)
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
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);        // offset +0
   fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_START); // offset +1
   /* deduced name */
   const guint32 send_nonce_buffer = nonce_buffer_size != 0;
   fpi_byte_writer_put_uint32_le(&writer, send_nonce_buffer); // offset +5
   fpi_byte_writer_put_uint32_le(&writer, nonce_buffer_size); // offset +9

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   /* no need to parse nonce buffer as it it not used here */

error:
   return ret;
}

gboolean send_enroll_add_image(FpiDeviceSynapticsMoc *self,
                               enroll_add_image_t *resp, GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 5;
   gsize recv_size = 82;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);            // offset +0
   fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_ADD_IMAGE); // offset +1

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   const guint8 *tuid_offset = NULL;
   guint32 enroll_stat_buffer_size;
   guint16 status;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   read_ok &= fpi_byte_reader_get_data(&reader, sizeof(db2_id_t), &tuid_offset);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &enroll_stat_buffer_size);
   if (read_ok) {
      if (enroll_stat_buffer_size != 60) {
         fp_err("qm struct size mismatch - expected: %u, got: %u", 60,
                enroll_stat_buffer_size);
         ret = FALSE;
         goto error;
      }
   }
   read_ok &= fpi_byte_reader_skip(&reader, 2); // skip over unknown
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &resp->progress);
   read_ok &= fpi_byte_reader_skip(&reader, 16);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->quality);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->redundant);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->rejected);
   read_ok &= fpi_byte_reader_skip(&reader, 4); // skip over unknown
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->template_cnt);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &resp->enroll_quality);
   read_ok &= fpi_byte_reader_skip(&reader, 6); // skip over unknown
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->status);
   read_ok &= fpi_byte_reader_skip(&reader, 4); // skip over unknown
   read_ok &= fpi_byte_reader_get_uint32_le(&reader,
                                            &resp->smt_like_has_fixed_pattern);

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      ret = FALSE;
      goto error;
   }

   // tuid is only given when progress is 100%
   if (resp->progress == 100) {
      memcpy(resp->tuid, tuid_offset, sizeof(resp->tuid));
   }

   fp_dbg("%s received:", __FUNCTION__);
   fp_dbg("\tprogress: %d", resp->progress);
   fp_dbg("\tquality: %d", resp->quality);
   fp_dbg("\tredundant: %d", resp->redundant);
   fp_dbg("\trejected: %d", resp->rejected);
   fp_dbg("\ttemplate count: %d", resp->template_cnt);
   fp_dbg("\tenroll quality: %d", resp->enroll_quality);
   fp_dbg("\tenroll status: %d", resp->status);
   fp_dbg("\tsmt like has fixed pattern: %d", resp->smt_like_has_fixed_pattern);

error:
   return ret;
}

gboolean send_enroll_commit(FpiDeviceSynapticsMoc *self,
                            guint8 *enroll_commit_data,
                            gsize enroll_commit_data_size, GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 13 + enroll_commit_data_size;
   gsize recv_size = 2;

   g_assert((enroll_commit_data_size != 0) && (enroll_commit_data != NULL));

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *send_data = g_malloc(sizeof(guint8) * send_size);

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL); // offset +0
   written &= fpi_byte_writer_put_uint32_le(&writer,
                                            ENROLL_SUBCMD_COMMIT); // offset +1
   written &= fpi_byte_writer_put_uint32_le(&writer, 0);           // offset +5
   written &= fpi_byte_writer_put_uint32_le(
       &writer, enroll_commit_data_size); // offset +9
   written &= fpi_byte_writer_put_data(&writer, enroll_commit_data,
                                       enroll_commit_data_size); // offset +13
   WRITTEN_CHECK(written);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));
error:
   return ret;
}

gboolean send_enroll_finish(FpiDeviceSynapticsMoc *self, GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 5;
   gsize recv_size = 2;
   fp_dbg("%s received:", __FUNCTION__);

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_ENROLL;
   FP_WRITE_UINT32_LE(&send_data[1], ENROLL_SUBCMD_FINISH);

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

error:
   return ret;
}

gboolean send_identify_match(FpiDeviceSynapticsMoc *self,
                             db2_id_t *tuids_to_match, gsize number_of_tuids,
                             gboolean *matched, enrollment_t *match,
                             GError *error)
{
   gboolean ret = TRUE;

   g_assert(self->tls.established);

   /*unused argument*/
   const gsize data_2_size = 0;
   const guint8 *data_2 = NULL;

   const guint8 *z_data = NULL;

   /*send only one type of data*/
   g_assert(((data_2_size == 0) && (data_2 == NULL)) ||
            ((number_of_tuids == 0) && (tuids_to_match == 0)));

   const gsize tuid_list_byte_size = sizeof(*tuids_to_match) * number_of_tuids;
   const gsize send_size = 13 + data_2_size + tuid_list_byte_size;
   gsize recv_size = 1602;

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *send_data = g_malloc(sizeof(guint8) * send_size);

   gboolean written = TRUE;
   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   written &= fpi_byte_writer_put_uint8(&writer,
                                        VCSFW_CMD_IDENTIFY_MATCH); // offset +0
   written &= fpi_byte_writer_put_uint32_le(&writer, 1);           // offset +1
   written &= fpi_byte_writer_put_uint32_le(&writer, data_2_size); // offset +5
   written &=
       fpi_byte_writer_put_uint32_le(&writer, number_of_tuids); // offset +9
   WRITTEN_CHECK(written);

   if (tuids_to_match != NULL) {
      fpi_byte_writer_put_data(&writer, *tuids_to_match,
                               number_of_tuids *
                                   tuid_list_byte_size); // offset +13
   } else if (data_2 != NULL) {
      fpi_byte_writer_put_data(&writer, data_2, data_2_size); // offset +13
   }

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, FALSE));

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
   } else if (status != RESPONSE_OK_1 && status != RESPONSE_OK_2 &&
              status != RESPONSE_OK_3) {
      fp_err("%s received error status: 0x%4x aka %s", __FUNCTION__, status,
             convert_sensor_status_to_string(status));
      goto error;
   }
   guint32 match_stats_len = 0;
   guint32 y_len = 0; // exact name not known
   guint32 z_len = 0; // exact name not known
   // we do not read this template id as it is sent in serialized as well and
   // from testing it is always the same
   read_ok &= fpi_byte_reader_skip(&reader, sizeof(db2_id_t)); // offset +2
   read_ok &=
       fpi_byte_reader_get_uint32_le(&reader, &match_stats_len); // offset +18
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &y_len);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &z_len);
   // do not read match stats as what is interpretable is not useful
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

   BOOL_CHECK(
       get_enrollment_data_from_serialized_container(z_data, z_len, match));

error:
   return ret;
}

gboolean send_get_image_metrics(FpiDeviceSynapticsMoc *self, guint32 type,
                                guint32 *recv_value, GError *error)
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
                                       &recv_size, TRUE));

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

gboolean send_event_config(FpiDeviceSynapticsMoc *self, guint32 event_mask,
                           GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 37;
   gsize recv_size = 66;

   const gint event_mask_cnt = 8;

   g_autofree guint8 *recv_data = NULL;
   g_autofree guint8 *send_data = g_malloc(sizeof(guint8) * send_size);

   fp_dbg("Setting event mask to: 0b%b", event_mask);

   FpiByteWriter writer;
   fpi_byte_writer_init_with_data(&writer, send_data, send_size, FALSE);
   fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_EVENT_CONFIG);
   /*repeat event mask 8 times*/
   for (gint i = 0; i < event_mask_cnt; ++i) {
      fpi_byte_writer_put_uint32_le(&writer, event_mask);
   }
   if (event_mask == 0) {
      fpi_byte_writer_put_uint32_le(&writer, 4);
   } else {
      fpi_byte_writer_put_uint32_le(&writer, 0);
   }

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   if (recv_size < 66) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }

   fp_dbg("Set event mask to %b", event_mask);

   guint32 event_seq_num = FP_READ_UINT16_LE(&recv_data[64]);
   fp_dbg("Current event sequence number is %d", event_seq_num);

error:
   return ret;
}

gboolean send_event_read(FpiDeviceSynapticsMoc *self, guint32 *recv_event_mask,
                         GError *error)
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
      FP_WRITE_UINT16_LE(&send_data[1], self->event_seq_num);

      if (!self->event_read_in_legacy_mode) {
         FP_WRITE_UINT32_LE(&send_data[5], 1);
      } else {
         send_size = 5; // shorten message if fallen back to legacy mode
      }

      BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size,
                                          &recv_data, &recv_size, FALSE));

      guint16 status = 0;
      guint16 recv_num_events = 0;
      guint16 recv_num_pending_events = 0;
      gboolean read_ok = TRUE;
      FpiByteReader reader;
      fpi_byte_reader_init(&reader, recv_data, recv_size);
      read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
      if (status != RESPONSE_OK_1 && status != RESPONSE_OK_2 &&
          status != RESPONSE_OK_3) {
         if (status == RESPONSE_BAD_PARAM_1 || status == RESPONSE_BAD_PARAM_2 ||
             status == RESPONSE_BAD_PARAM_3) {
            fp_dbg(
                "Received status 0x%04x on event read, falling back to legacy "
                "event reading",
                status);
            self->event_read_in_legacy_mode = TRUE;
            free(recv_data);
            continue;
         } else {
            ret = FALSE;
            goto error;
         }
      }

      read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_events);
      read_ok &=
          fpi_byte_reader_get_uint16_le(&reader, &recv_num_pending_events);
      fp_dbg("Received num_events: %d, num_pending_events: %d", recv_num_events,
             recv_num_pending_events);

      /*read event types*/
      for (int i = 0; i < recv_num_events; ++i) {
         guint8 event;
         read_ok &= fpi_byte_reader_get_uint8(&reader, &event);
         if (read_ok) {
            *recv_event_mask |= 1 << event;
         }
         /* skip over unknown stuff */
         read_ok &= fpi_byte_reader_skip(&reader, 11);
         if (!read_ok) {
            break;
         }
      }

      if (!read_ok) {
         g_warning(
             "Transfer in version response to event read query was too short");
         error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
         ret = FALSE;
         goto error;
      }

      /*update event sequence number*/
      self->event_seq_num = (self->event_seq_num + recv_num_events) & 0xffff;
      fp_dbg("New event sequence number: %d", self->event_seq_num);

      free(recv_data);

      /*parse number of pending events*/
      if (self->event_read_in_legacy_mode) {
         g_assert(recv_num_pending_events >= recv_num_events);
         self->num_pending_events = recv_num_pending_events - recv_num_events;
      } else {
         self->num_pending_events = recv_num_pending_events;
      }
   } while (self->num_pending_events > 0);

error:
   return ret;
}

/* prints DB2 info on debug output and stores numbers of current users,
 * templates and payloads */
gboolean send_db2_info(FpiDeviceSynapticsMoc *self, GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 2;
   gsize recv_size = 64;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_DB2_GET_DB_INFO;
   send_data[1] = 1;

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   gboolean read_ok = TRUE;
   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);
   // no need to read status again
   read_ok &= fpi_byte_reader_skip(&reader, sizeof(guint16));
   db2_info_t db2_info;
   read_ok &= parse_db2_info(&reader, &db2_info);
   READ_OK_CHECK(read_ok);

   debug_print_db2_info(&db2_info);

   self->storage.num_current_users = db2_info.num_current_users;
   self->storage.num_current_templates = db2_info.num_current_templates;
   self->storage.num_current_payloads = db2_info.num_current_payloads;

error:
   return ret;
}

gboolean add_enrollment(FpiDeviceSynapticsMoc *self, guint8 *user_id,
                        guint8 finger_id, db2_id_t tuid, GError *error)
{
   // FIXME: for debug only
   g_assert(sizeof(db2_id_t) == 0x10);
   g_assert(sizeof(finger_id) == 0x1);

   gboolean ret = TRUE;

   guint container_cnt = 3;
   container_item_t container[3];

   container[0].id = ENROLL_TAG_TEMPLATE_ID;
   container[0].data = tuid;
   container[0].data_size = sizeof(db2_id_t);

   container[1].id = ENROLL_TAG_USER_ID;
   container[1].data = user_id;
   container[1].data_size = sizeof(user_id_t);

   container[2].id = ENROLL_TAG_FINGER_ID;
   container[2].data = &finger_id;
   container[2].data_size = sizeof(finger_id);

   fp_dbg("Adding enrollment with:");
   fp_dbg("\ttemplate ID:");
   print_array(tuid, sizeof(db2_id_t));
   fp_dbg("\tuser ID:");
   print_array(user_id, sizeof(user_id_t));
   fp_dbg("\tfinger ID: %u", finger_id);

   g_autofree guint8 *enroll_commit_data = NULL;
   gsize enroll_commit_data_size = 0;
   BOOL_CHECK(serialize_container(container, container_cnt, &enroll_commit_data,
                                  &enroll_commit_data_size));

   fp_dbg("serialized container:");
   print_array(enroll_commit_data, enroll_commit_data_size);

   BOOL_CHECK(send_enroll_commit(self, enroll_commit_data,
                                 enroll_commit_data_size, error));

error:
   return ret;
}

gboolean send_db2_format(FpiDeviceSynapticsMoc *self, GError *error)
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
                                       &recv_size, TRUE));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint new_partition_version = 0;
   read_ok &= fpi_byte_reader_skip(&reader, 2); // no need to read status again
   read_ok &= fpi_byte_reader_skip(&reader, 4); // unknown4
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &new_partition_version);

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }
   fp_dbg("Format succeeded with new partition version: %d",
          new_partition_version);

error:
   return ret;
}

gboolean send_db2_delete_object(FpiDeviceSynapticsMoc *self,
                                obj_type_t obj_type, db2_id_t *obj_id,
                                GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   gsize recv_size = 4;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];
   send_data[0] = VCSFW_CMD_DB2_DELETE_OBJECT;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, sizeof(db2_id_t));

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 num_deleted_objects = 0;
   read_ok &= fpi_byte_reader_skip(&reader, 2); // no need to read status again
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_deleted_objects);

   if (!read_ok) {
      g_warning("Transfer in to version DB2 delete object was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }
   fp_dbg("Delete object succeeded with number of deleted objects: %d",
          num_deleted_objects);

error:
   return ret;
}

gboolean send_db2_get_object_list(FpiDeviceSynapticsMoc *self,
                                  obj_type_t obj_type, db2_id_t obj_id,
                                  db2_id_t **obj_list, guint16 *obj_list_len,
                                  GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   gsize recv_size;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   // update num_current_users
   BOOL_CHECK(send_db2_info(self, error));
   switch (obj_type) {
   case OBJ_TYPE_USERS:
      recv_size = 4 + 16 * self->storage.num_current_users;
      break;
   case OBJ_TYPE_TEMPLATES:
      recv_size = 4 + 16 * self->storage.num_current_templates;
      break;
   case OBJ_TYPE_PAYLOADS:
      recv_size = 4 + 16 * self->storage.num_current_payloads;
      break;
   }

   send_data[0] = VCSFW_CMD_DB2_GET_OBJECT_LIST;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, sizeof(db2_id_t));

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   read_ok &= fpi_byte_reader_skip(&reader, 2); // no need to read status again
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, obj_list_len);
   READ_OK_CHECK(read_ok);

   fp_dbg("Object id");
   print_array(obj_id, sizeof(db2_id_t));
   fp_dbg("of type %d has object list with %d elements:", obj_type,
          *obj_list_len);

   *obj_list = g_malloc(*obj_list_len * sizeof(db2_id_t));

   for (int i = 0; i < *obj_list_len; ++i) {
      const guint8 *obj_id_offset;
      read_ok &=
          fpi_byte_reader_get_data(&reader, sizeof(db2_id_t), &obj_id_offset);
      if (read_ok) {
         memcpy(&((*obj_list)[i]), obj_id_offset, sizeof(db2_id_t));
         fp_dbg("\tat position %d is:", i);
         print_array((*obj_list)[i], sizeof(db2_id_t));
      }
   }

error:
   return ret;
}

gboolean send_db2_get_object_info(FpiDeviceSynapticsMoc *self,
                                  obj_type_t obj_type, db2_id_t obj_id,
                                  guint8 **obj_info, gsize *obj_info_size,
                                  GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   *obj_info_size = obj_type == OBJ_TYPE_USERS ? 12 : 52;

   guint8 send_data[send_size];

   send_data[0] = VCSFW_CMD_DB2_GET_OBJECT_INFO;
   FP_WRITE_UINT32_LE(&send_data[1], obj_type);
   memcpy(&send_data[5], obj_id, sizeof(db2_id_t));

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, obj_info,
                                       obj_info_size, TRUE));

   fp_dbg("Object with id");
   print_array(obj_id, sizeof(db2_id_t));
   fp_dbg("of type %d has info:", obj_type);
   print_array(*obj_info, *obj_info_size);

error:
   if (!ret && *obj_info != NULL) {
      free(*obj_info);
      *obj_info = NULL;
   }
   return ret;
}

static gboolean get_payload_data_size(FpiDeviceSynapticsMoc *self,
                                      db2_id_t payload_id,
                                      guint *payload_data_size, GError *error)
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
   print_array(payload_id, sizeof(db2_id_t));
   fp_dbg("of type %d has payload data size: %d", OBJ_TYPE_PAYLOADS,
          *payload_data_size);

error:
   return ret;
}

gboolean send_db2_get_object_data(FpiDeviceSynapticsMoc *self,
                                  obj_type_t obj_type, db2_id_t obj_id,
                                  guint8 **obj_data, guint *obj_data_size,
                                  GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 21;
   gsize recv_size;

   g_autofree guint8 *recv_data = NULL;
   guint8 send_data[send_size];

   // update num_current_users
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
   memcpy(&send_data[5], obj_id, sizeof(db2_id_t));

   BOOL_CHECK(synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                       &recv_size, TRUE));

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   read_ok &= fpi_byte_reader_skip(&reader, 2); // no need to read status again
   read_ok &= fpi_byte_reader_skip(&reader, 2); // skip over unknown
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, obj_data_size);
   fp_dbg("Received object data of length %u", *obj_data_size);
   read_ok &= fpi_byte_reader_dup_data(&reader, *obj_data_size, obj_data);

   READ_OK_CHECK(read_ok);

error:
   return ret;
}

gboolean get_event_data(FpiDeviceSynapticsMoc *self, guint8 *event_buffer,
                        gsize event_buffer_size)
{
   gboolean ret = TRUE;

   const guint8 recv_size = 7;
   g_assert(event_buffer_size >= recv_size);

   g_autoptr(FpiUsbTransfer) transfer = NULL;
   GError *error = NULL;

   /* receive data */
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk(transfer, USB_EP_INTERRUPT, event_buffer_size);
   if (!fpi_usb_transfer_submit_sync(transfer, 60000, &error))
      goto error;

   fp_dbg("Events raw resp:");
   print_array(transfer->buffer, transfer->actual_length);

   if (transfer->actual_length > event_buffer_size) {
      fp_warn("Unexpected length of response in %s, got: %lu, expected: %lu, "
              "received array: ",
              __func__, transfer->actual_length, event_buffer_size);
      print_array(transfer->buffer, transfer->actual_length);
   }

   memcpy(event_buffer, transfer->buffer, transfer->actual_length);

error:
   return ret;
}

gboolean wait_for_events_blocking(FpiDeviceSynapticsMoc *self,
                                  guint32 event_mask, GError *error)
{
   gboolean ret = TRUE;
   /*
    * Needs to be larger than 7 as that is the size of response for
    * get_event_data */
   const gsize event_buffer_size = 16;
   guint8 event_buffer[event_buffer_size];

   guint32 recv_event_mask = 0;
   while ((recv_event_mask & event_mask) != event_mask) {

      if (self->num_pending_events <= 0) {
         fp_info("Waiting for sensor to have events");
         while (TRUE) {
            BOOL_CHECK(get_event_data(self, event_buffer, event_buffer_size));
            // we will read the events in the next part, here just read the
            // event sequence number

            guint16 recv_event_seq_num = FP_READ_UINT16_LE(&event_buffer[6]);
            if (self->event_seq_num != recv_event_seq_num) {
               break;
            }
         }
      }

      fp_info("Reading sensor events");
      fp_dbg("Num pending bevents: %d", self->num_pending_events);
      BOOL_CHECK(send_event_read(self, &recv_event_mask, error));
      fp_dbg("Num pending aevents: %d", self->num_pending_events);
      fp_dbg("Recv event mask is: %b, requested is: %b", recv_event_mask,
             event_mask);
   }

error:
   return ret;
}
