#include "communication.h"
#include "drivers_api.h"
#include "fpi-byte-reader.h"
#include "fpi-usb-transfer.h"
#include "other_constants.h"
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
   default:
      ret = "UNKNOWN_STATUS";
   }

   return ret;
}

gboolean synaptics_secure_connect(FpiDeviceSynapticsMoc *self,
                                  guint8 *send_data, gsize send_len,
                                  guint8 **recv_data, gsize *recv_len,
                                  gboolean check_status)
{
   g_autoptr(FpiUsbTransfer) transfer = NULL;
   GError *error = NULL;
   guint16 status = 0xffff;

   const int num_attempts = 3;
   const int status_header_len = 2;

   fp_dbg("Cmd send id: 0x%x", send_data[0]);
   fp_dbg("Cmd send data:");
   for (int i = 0; i < send_len; ++i) {
      printf("%02x", send_data[i]);
   }

   printf("\n");

   for (int i = 0; i < num_attempts; ++i) {
      fp_dbg("send attempt: %d", i);

      /* send data */
      transfer = fpi_usb_transfer_new(FP_DEVICE(self));
      fpi_usb_transfer_fill_bulk(transfer, USB_EP_REQUEST, send_len);
      transfer->short_is_error = TRUE;
      memcpy(transfer->buffer, send_data, send_len);
      if (!fpi_usb_transfer_submit_sync(transfer, USB_TRANSFER_WAIT_TIMEOUT_MS,
                                        &error)) {

         goto error;
      }

      fpi_usb_transfer_unref(transfer);

      /* receive data */
      transfer = fpi_usb_transfer_new(FP_DEVICE(self));
      fpi_usb_transfer_fill_bulk(transfer, USB_EP_REPLY, *recv_len);
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

   fp_dbg("Cmd receive id: 0x%02x", send_data[0]);
   fp_dbg("\tRecv_len: %lu, Transfer_len: %lu, Transfer->actual_length: %lu",
          *recv_len, transfer->length, transfer->actual_length);

   /* response can be shorter, e.g. on error */
   *recv_len = transfer->actual_length;

   *recv_data = g_malloc((*recv_len) * sizeof(guint8));
   memcpy(*recv_data, transfer->buffer, transfer->actual_length);

   fp_dbg("Cmd recv data of len %lu:", transfer->actual_length);
   for (int i = 0; i < transfer->actual_length; ++i) {
      printf("%02x", transfer->buffer[i]);
   }
   printf("\n");

   return TRUE;
error:
   fpi_usb_transfer_unref(transfer);
   g_error("Error in function %s: %d aka '%s'", __FUNCTION__, error->code,
           error->message);
   if (*recv_data != NULL) {
      g_free(*recv_data);
      *recv_data = NULL;
   }
   return FALSE;
}

gboolean send_get_version(FpiDeviceSynapticsMoc *self, get_version_t *resp,
                          GError *error)
{
   gboolean ret = TRUE;

   const gsize send_size = 1;
   gsize recv_size = 38;

   guint8 *recv_data = NULL;
   guint8 *send_data = g_malloc(sizeof(guint8) * send_size);
   send_data[0] = VCSFW_CMD_GET_VERSION;

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      ret = FALSE;
      goto error;
   }

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
   // TODO: seems like there is something wrong here
   // if (fpi_byte_reader_get_data(&reader, sizeof(resp->serial_number),
   // &data))
   //    memcpy(resp->serial_number, data, sizeof(resp->serial_number));
   // else
   //    read_ok = FALSE;
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
   if (send_data != NULL) {
      g_free(send_data);
   }
   if (recv_data != NULL) {
      g_free(recv_data);
   }
   return ret;
}

gboolean send_test(FpiDeviceSynapticsMoc *self, GError *error)
{
   fp_dbg("sending test data:");
   guint8 test_data[] = {
       0x44, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x41, 0x01, 0x00,
       0x00, 0x3d, 0x03, 0x03, 0x66, 0xb1, 0xe2, 0xa9, 0xbe, 0x4f, 0x56,
       0xaa, 0xc1, 0x52, 0x6e, 0x2b, 0x60, 0x63, 0xb4, 0x28, 0x4d, 0x13,
       0xaf, 0x6a, 0x5c, 0x37, 0xa3, 0x5c, 0x00, 0x88, 0xe4, 0x14, 0xef,
       0x9e, 0x88, 0x5a, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x02, 0xc0, 0x2e, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02,
       0x00, 0x17, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00};

   gboolean ret = TRUE;

   gsize recv_size = 0x100;
   guint8 *recv_data = NULL;

   if (!synaptics_secure_connect(self, test_data, sizeof(test_data), &recv_data,
                                 &recv_size, FALSE)) {
      fp_err("error while sending test command");
      ret = FALSE;
      goto error;
   }

   // fp_dbg("test response:");
   // for (int i = 0; i < recv_size; ++i) {
   //    printf("%02x", recv_data[i]);
   // }

   return TRUE;
error:
   if (recv_data != NULL) {
      g_free(recv_data);
   }
   return ret;
}

gboolean send_cmd_frame_acq(FpiDeviceSynapticsMoc *self, guint8 frame_flags,
                            GError *error)
{
   const gsize send_size = 17;
   gsize recv_size = 2;

   const int no_retries = 3;

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

   guint16 status;
   for (int i = 0; i < no_retries; ++i) {
      /*Do not check the response status as there is a status on which we
       * should send the command again*/
      if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                    &recv_size, FALSE)) {
         // TODO: mark error and free
      }

      status = FP_READ_UINT16_LE(recv_data);
      if (status == RESPONSE_OK_1 || status == RESPONSE_OK_2 ||
          status == RESPONSE_OK_3) {
         break;
      } else if (status == RESPONSE_PROCESSING_FRAME) {
         fp_dbg("received status RESPONSE_PROCESSING_FRAME, retrying");
         continue;
      } else {
         goto error;
      }
   }

   free(send_data);
   free(recv_data);

   return TRUE;
error:
   return FALSE;
}

gboolean send_cmd_frame_finish(FpiDeviceSynapticsMoc *self, GError *error)
{
   const gsize send_size = 1;
   gsize recv_size = 2;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_FRAME_FINISH;

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
      goto error;
   }

   free(send_data);
   free(recv_data);

   return TRUE;
error:
   return FALSE;
}

gboolean send_enroll_start(FpiDeviceSynapticsMoc *self, GError *error)
{
   const gsize nonce_buffer_size = 0;

   const gsize send_size = 13;
   gsize recv_size = 5;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_ENROLL;
   FP_WRITE_UINT32_LE(&send_data[1], ENROLL_SUBCMD_START);
   /*deduced name*/
   const guint32 send_nonce_buffer = nonce_buffer_size != 0;
   FP_WRITE_UINT32_LE(&send_data[5], send_nonce_buffer);
   FP_WRITE_UINT32_LE(&send_data[9], nonce_buffer_size);

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
      goto error;
   }

   /*no need to parse nonce buffer as it it not used here*/

   free(send_data);
   free(recv_data);

   return TRUE;
error:
   return FALSE;
}

gboolean send_enroll_add_image(FpiDeviceSynapticsMoc *self,
                               enroll_add_image_t *resp, GError *error)
{
   const gsize send_size = 5;
   gsize recv_size = 82;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_ENROLL;
   FP_WRITE_UINT32_LE(&send_data[1], ENROLL_SUBCMD_ADD_IMAGE);

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
      goto error;
   }

   free(send_data);

   FpiByteReader reader;
   fpi_byte_reader_init(&reader, recv_data, recv_size);

   gboolean read_ok = TRUE;
   guint16 status;
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &resp->progress);
   read_ok &= fpi_byte_reader_skip(&reader, 16);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->quality);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->redundant);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->rejected);
   read_ok &= fpi_byte_reader_skip(&reader, 4);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->template_cnt);
   read_ok &= fpi_byte_reader_get_uint16_le(&reader, &resp->enroll_quality);
   read_ok &= fpi_byte_reader_skip(&reader, 6);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader, &resp->status);
   read_ok &= fpi_byte_reader_skip(&reader, 4);
   read_ok &= fpi_byte_reader_get_uint32_le(&reader,
                                            &resp->smt_like_has_fixed_pattern);

   free(recv_data);

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }

   // tuid is only given when progress is 100%
   if (resp->progress == 100) {
      memcpy(resp->tuid, &recv_data[4], sizeof(resp->tuid));
   }

   fp_dbg("%s received:", __FUNCTION__);
   fp_dbg("\tprogress: %d", resp->progress);
   fp_dbg("\tquality: %d", resp->quality);
   fp_dbg("\tredundant: %d", resp->redundant);
   fp_dbg("\trejectep: %d", resp->rejected);
   fp_dbg("\ttemplate count: %d", resp->template_cnt);
   fp_dbg("\tenroll quality: %d", resp->enroll_quality);
   fp_dbg("\tenroll status: %d", resp->status);
   fp_dbg("\tsmt like has fixed pattern: %d", resp->smt_like_has_fixed_pattern);

   return TRUE;
error:
   return FALSE;
}

gboolean send_enroll_commit(FpiDeviceSynapticsMoc *self,
                            guint8 *enroll_commit_data,
                            gsize enroll_commit_data_size, GError *error)
{
   const gsize send_size = 12 + enroll_commit_data_size;
   gsize recv_size = 2;

   g_assert((enroll_commit_data_size != 0) && (enroll_commit_data != NULL));

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_GET_VERSION;
   FP_WRITE_UINT32_LE(&send_data[1], ENROLL_SUBCMD_COMMIT);
   FP_WRITE_UINT32_LE(&send_data[5], 0);
   FP_WRITE_UINT32_LE(&send_data[9], enroll_commit_data_size);
   memcpy(&send_data[13], enroll_commit_data, enroll_commit_data_size);

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
   }

   free(send_data);
   free(recv_data);

   return TRUE;
error:
   return FALSE;
}

gboolean send_enroll_finish(FpiDeviceSynapticsMoc *self, GError *error)
{
   const gsize send_size = 5;
   gsize recv_size = 2;
   fp_dbg("%s received:", __FUNCTION__);

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_ENROLL;
   FP_WRITE_UINT32_LE(&send_data[1], ENROLL_SUBCMD_FINISH);

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
   }

   free(send_data);

   return TRUE;
error:
   return FALSE;
}

gboolean send_identify_match(FpiDeviceSynapticsMoc *self, tuid *tuid_list,
                             gsize number_of_tuids, GError *error)
{
   g_assert(self->tls.established);

   /*unused argument*/
   const gsize data_2_size = 0;
   const guint8 *data_2 = NULL;

   /*send only one type of data*/
   g_assert(((data_2_size == 0) && (data_2 == NULL)) ||
            ((number_of_tuids == 0) && (tuid_list == 0)));

   const gsize tuid_list_byte_size = sizeof(*tuid_list) * number_of_tuids;
   const gsize send_size = 13 + data_2_size + tuid_list_byte_size;
   gsize recv_size = 1602;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }

   send_data[0] = VCSFW_CMD_IDENTIFY_MATCH;
   FP_WRITE_UINT32_LE(&send_data[1], 1);
   FP_WRITE_UINT32_LE(&send_data[5], data_2_size);
   FP_WRITE_UINT32_LE(&send_data[9], number_of_tuids);
   if (tuid_list != NULL) {
      memcpy(&send_data[13], tuid_list, number_of_tuids * tuid_list_byte_size);
   } else if (data_2 != NULL) {
      memcpy(&send_data[13], data_2, data_2_size);
   }

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, FALSE)) {
      // TODO: mark error and free
   }

   free(send_data);

   // const guint16 status = FP_READ_UINT16_LE(recv_data);

   // FpiByteReader reader;
   // fpi_byte_reader_init(&reader, recv_data, recv_size);

   /* FIXME: not implemented yet*/

   free(recv_data);

   return TRUE;
error:
   return FALSE;
}

gboolean send_get_image_metrics(FpiDeviceSynapticsMoc *self, guint32 type,
                                guint32 *recv_value, GError *error)
{
   const gsize send_size = 5;
   gsize recv_size = 10;

   g_assert(type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE ||
            type == MIS_IMAGE_METRICS_IMG_QUALITY);

   if (type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE) {
      recv_size = 14;
   } else if (type == MIS_IMAGE_METRICS_IMG_QUALITY) {
      recv_size = 70;
   }

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_GET_IMAGE_METRICS;

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
   }

   free(send_data);

   // FIXME: this needs recv_size changing inside of command send
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
   if (recv_data_size == 0) {
      fp_err("Unable to query img metrics now");
   } else if (type == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE &&
              recv_data_size ==
                  MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE_DATA_SIZE) {
      /*read finger coverage*/
      read_ok &= fpi_byte_reader_get_uint32_le(&reader, recv_value);
   } else if (type == MIS_IMAGE_METRICS_IMG_QUALITY &&
              recv_data_size ==
                  MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE_DATA_SIZE) {
      /*read IPL finger coverage*/
      read_ok &= fpi_byte_reader_get_uint32_le(&reader, recv_value);
      /*not reading the other 4 bytes as the interpretation is unknown*/
   } else {
      fp_err("Image metrics 0x%x were not supported; got %u bytes as data size",
             type, recv_data_size);
   }

   free(recv_data);

   if (!read_ok) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }

   fp_dbg("%s received:", __FUNCTION__);
   fp_dbg("\tImage metrics of type 0x%x have data: %d", type, *recv_value);

   return TRUE;
error:
   return FALSE;
}

gboolean send_event_config(FpiDeviceSynapticsMoc *self, guint32 event_mask,
                           GError *error)
{
   const gsize send_size = 37;
   gsize recv_size = 66;

   const gint event_mask_cnt = 8;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_EVENT_CONFIG;
   /*repeat event mask 8 times*/
   gsize offset = 1;
   for (gint i = 0; i < event_mask_cnt; ++i) {
      FP_WRITE_UINT32_LE(&send_data[offset], event_mask);
      offset += 4;
   }
   if (event_mask == 0) {
      FP_WRITE_UINT32_LE(&send_data[33], 4);
   } else {
      FP_WRITE_UINT32_LE(&send_data[33], 0);
   }

   if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                 &recv_size, TRUE)) {
      // TODO: mark error and free
   }

   free(send_data);

   if (recv_size < 66) {
      g_warning("Transfer in version response to version query was too short");
      error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
      goto error;
   }

   free(recv_data);

   fp_dbg("Set event mask to 0x%x", event_mask);

   guint32 event_seq_num = FP_READ_UINT16_LE(&recv_data[64]);
   fp_dbg("Current event sequence number is %d", event_seq_num);

   return TRUE;
error:
   return FALSE;
}

gboolean send_event_read(FpiDeviceSynapticsMoc *self, guint8 *event_buffer,
                         gsize event_buffer_size, gint *num_events,
                         GError *error)
{
   const guint16 max_num_events_in_resp = 32;

   gsize recv_size = 6 + 12 * max_num_events_in_resp;
   gsize send_size = 9;

   guint8 *recv_data = NULL;
   guint8 *send_data = malloc(sizeof(guint8) * send_size);
   if (send_data == NULL) {
      // TODO: how do they check for malloc errors
      goto error;
   }
   send_data[0] = VCSFW_CMD_EVENT_READ;
   FP_WRITE_UINT16_LE(&send_data[3], max_num_events_in_resp);

   while (TRUE) {
      /*is here as we need to update the sequence number*/
      FP_WRITE_UINT16_LE(&send_data[1], self->event_seq_num);

      if (!self->event_read_in_legacy_mode) {
         FP_WRITE_UINT32_LE(&send_data[5], 1);
      } else {
         send_size = 5; // shorten message if fallen back to legacy mode
      }

      if (!synaptics_secure_connect(self, send_data, send_size, &recv_data,
                                    &recv_size, FALSE)) {
         // TODO: mark error and free
         goto error;
      }

      g_assert(recv_size >= 2);

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
            fp_dbg("Received status %d on event read, falling back to legacy "
                   "event reading",
                   status);
            self->event_read_in_legacy_mode = TRUE;
            free(recv_data);
            continue;
         } else {
            goto error;
         }
      }

      read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_events);
      read_ok &=
          fpi_byte_reader_get_uint16_le(&reader, &recv_num_pending_events);
      fp_dbg("warning: Received num_events: %d, num_pending_events: %d",
             recv_num_events, recv_num_pending_events);

      /*read event types*/
      for (int i = 0; i < recv_num_events; ++i) {
         // FIXME: add to some sort of queue
         if ((*num_events) >= event_buffer_size) {
            read_ok &= fpi_byte_reader_get_uint8(
                &reader, &event_buffer[(*num_events)++]);
         } else {
            guint8 event = 0;
            read_ok &= fpi_byte_reader_get_uint8(&reader, &event);
            fp_err("warn: unable to store more events, discarding event: %d",
                   event);
         }
         /* skip over unknown stuff */
         read_ok &= fpi_byte_reader_skip(&reader, 11);
      }

      if (!read_ok) {
         g_warning(
             "Transfer in version response to version query was too short");
         error = fpi_device_error_new(FP_DEVICE_ERROR_PROTO);
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
   }

   free(send_data);

   return TRUE;
error:
   return FALSE;
}
