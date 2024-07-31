#include "communication.h"
#include "drivers_api.h"
#include "fpi-byte-reader.h"

static const char *convert_sensor_status_to_string(uint16_t status)
{
   char *ret;

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
   default:
      ret = "UNKNOWN_STATUS";
   }

   return ret;
}

static gboolean synaptics_secure_connect(FpiDeviceSynapticsMoc *self,
                                         uint8_t *send_data, size_t send_len,
                                         uint8_t **recv_data, size_t recv_len,
                                         gboolean check_status)
{
   g_autoptr(FpiUsbTransfer) transfer = NULL;
   GError *error = NULL;
   // TODO: make a define
   guint16 status = 0xffff;
   const guint8 *data;
   g_autofree gchar *serial = NULL;
   gboolean retry = TRUE;
   FpiByteReader reader;

   const int num_attempts = 3;
   const int status_header_len = 2;

   fp_dbg("Cmd send id: %d", send_data[0]);

   for (int i = 0; i < num_attempts; ++i) {
      transfer = fpi_usb_transfer_new(FP_DEVICE(self));
      fpi_usb_transfer_fill_bulk(transfer, USB_EP_REQUEST,
                                 SENSOR_FW_CMD_HEADER_LEN);
      transfer->short_is_error = TRUE;
      memcpy(transfer->buffer, send_data, send_len);
      if (!fpi_usb_transfer_submit_sync(transfer, 1000, &error))
         goto error;

      g_clear_pointer(&transfer, fpi_usb_transfer_unref);
      transfer = fpi_usb_transfer_new(FP_DEVICE(self));
      fpi_usb_transfer_fill_bulk(transfer, USB_EP_REPLY, 120);
      if (!fpi_usb_transfer_submit_sync(transfer, 1000, &error))
         goto error;

      if (transfer->actual_length < status_header_len) {
         g_warning("Response transfer was too short");
         error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
         goto error;
      }

      status = FP_READ_UINT16_LE(transfer->buffer);
      if (status != UNKNOWN_RESPONSE_ON_WHICH_SEND_AGAIN) {
         break;
      }
   }

   if ((check_status) && (status != RESPONSE_OK_1) &&
       (status != RESPONSE_OK_2) && (status != RESPONSE_OK_3)) {
      g_warning("Device responded with error: 0x%04x", status);
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }

   fp_dbg("Cmd receive id: %d", send_data[0]);
   fp_dbg("\tRecv_len: %lu, Transfer_len: %lu, Transfer->actual_length: %lu",
          recv_len, transfer->length, transfer->actual_length);

   g_assert(recv_len == transfer->actual_length);

   *recv_data = malloc(recv_len * sizeof(guint8));
   memcpy(*recv_data, transfer->buffer, transfer->actual_length);

   return TRUE;
error:
   g_error("Error in function %s: %d aka '%s'", __FUNCTION__, error->code,
           error->message);
   return FALSE;
}

gboolean send_cmd_get_version(FpiDeviceSynapticsMoc *self, get_version_t *resp,
                              GError *error)
{
   const gsize send_size = 1;
   const gsize recv_size = 38;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   send_data[0] = VCSFW_CMD_GET_VERSION;

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 recv_size, TRUE)) {
      // TODO: mark error and free
   }

   free(send_data);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 status;
   guint8 *data;
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
   // TODO: seems like there is something wrong here
   if (fpi_byte_reader_get_data(&reader, sizeof(resp->serial_number), &data))
      memcpy(resp->serial_number, data, sizeof(resp->serial_number));
   else
      read_ok = FALSE;
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->security);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->interface);
   read_ok &= fpi_byte_reader_skip(&reader, 8);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->device_type);
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->provision_state);
   // rest is unread for now

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
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

   return TRUE;
error:
   return FALSE;
}

gboolean send_cmd_frame_acq(FpiDeviceSynapticsMoc *self, guint8 frame_flags,
                            GError *error)
{
   const gsize send_size = 17;
   const gsize recv_size = 2;

   /* These were the only frame flags used, which enabled a bit of
    * simplification.*/
   g_assert((frame_flags == 7) || (frame_flags == 15));

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_FRAME_ACQ;
   /*I was unable to find the meaning of these values, so I did not abstract
    * them into constants.*/
   if (frame_flags == 7) {
      FP_WRITE_UINT32_LE(&(send_data[1]), 4116);
   } else {
      FP_WRITE_UINT32_LE(&(send_data[1]), 12);
   }
   FP_WRITE_UINT32_LE(&(send_data[5]), 1); // number of frames
   FP_WRITE_UINT16_LE(&(send_data[9]), 0);
   send_data[11] = 0;
   send_data[12] = 8;
   send_data[13] = 1;
   send_data[14] = 1;
   send_data[15] = 1;
   send_data[16] = 0;

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 recv_size, TRUE)) {
      // TODO: mark error and free
   }

   free(send_data);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 status;
   guint8 *data;
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
   if (fpi_byte_reader_get_data(&reader, sizeof(resp->serial_number), &data))
      memcpy(resp->serial_number, data, sizeof(resp->serial_number));
   else
      read_ok = FALSE;
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->security);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->interface);
   read_ok &= fpi_byte_reader_skip(&reader, 8);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->device_type);
   read_ok &= fpi_byte_reader_skip(&reader, 2);
   read_ok &= fpi_byte_reader_get_uint8(&reader, &resp->provision_state);
   // rest is unread for now

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
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

   return TRUE;
error:
   return FALSE;
}
