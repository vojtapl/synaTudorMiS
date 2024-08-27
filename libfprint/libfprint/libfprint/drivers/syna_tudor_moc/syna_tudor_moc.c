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

#include "communication.c"
#include "device.h"
#include "drivers_api.h"
#include "fpi-log.h"
#include "syna_tudor_moc.h"
#include "tls.c"
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

/* #define STORAGE_ENABLED */

static db2_id_t cache_template_id = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff};

G_DEFINE_TYPE(FpiDeviceSynaTudorMoc, fpi_device_syna_tudor_moc, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00C9, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00D1, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00E7, },
    /* only 00FF is tested */
    {
        .vid = SYNAPTICS_VENDOR_ID,
        .pid = 0x00FF,
    },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0124, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0169, },
    {.vid = 0, .pid = 0, .driver_data = 0}, /* terminating entry */
};

static gboolean capture_image(FpiDeviceSynaTudorMoc *self, guint8 frame_flags,
                              GError **error)
{
   gboolean ret = TRUE;

   BOOL_CHECK(send_event_config(self, EV_FRAME_READY, error));

   BOOL_CHECK(send_frame_acq(self, frame_flags, error));

   fpi_device_report_finger_status(FP_DEVICE(self), FP_FINGER_STATUS_NEEDED);
   BOOL_CHECK(send_event_config(self, EV_FRAME_READY | EV_FINGER_DOWN, error));

   BOOL_CHECK(
       wait_for_events_blocking(self, EV_FRAME_READY | EV_FINGER_DOWN, error));
   fpi_device_report_finger_status(FP_DEVICE(self), FP_FINGER_STATUS_PRESENT);

   BOOL_CHECK(send_event_config(self, NO_EVENTS, error));

   BOOL_CHECK(send_frame_finish(self, error));

error:
   return ret;
}

static gboolean get_enrollment_data(FpiDeviceSynaTudorMoc *self,
                                    db2_id_t payload_id,
                                    enrollment_t *enrollment, GError **error)
{
   gboolean ret = TRUE;

   guint obj_data_size;
   g_autofree guint8 *obj_data;
   BOOL_CHECK(send_db2_get_object_data(self, OBJ_TYPE_PAYLOADS, payload_id,
                                       &obj_data, &obj_data_size, error));

   BOOL_CHECK(get_enrollment_data_from_serialized_container(
       obj_data, obj_data_size, enrollment, error));

error:
   return ret;
}

static gboolean get_enrollments(FpiDeviceSynaTudorMoc *self,
                                enrollment_t **enrollments,
                                guint *enrollments_cnt, GError **error)
{
   gboolean ret = TRUE;

   guint allocated_enrollments_cnt = 5;
   *enrollments = g_malloc_n(allocated_enrollments_cnt, sizeof(enrollment_t));

   guint16 template_id_list_len = 0;
   g_autofree db2_id_t *template_id_list = NULL;
   g_autofree db2_id_t *payload_list = NULL;

   BOOL_CHECK(send_db2_get_object_list(self, OBJ_TYPE_TEMPLATES,
                                       cache_template_id, &template_id_list,
                                       &template_id_list_len, error));
   if (template_id_list_len == 0) {
      fp_dbg("received empty template_id_list");
      goto error;
   }

   for (int i = 0; i < template_id_list_len; ++i) {
      guint16 payload_list_len = 0;
      fp_dbg("Getting payloads for template_id:");
      fp_dbg_large_hex(template_id_list[i], DB2_ID_SIZE);
      BOOL_CHECK(send_db2_get_object_list(self, OBJ_TYPE_PAYLOADS,
                                          template_id_list[i], &payload_list,
                                          &payload_list_len, error));
      if (payload_list_len == 0) {
         fp_warn("No payload data for enrollment with template_id:");
         fp_dbg_large_hex(template_id_list[i], DB2_ID_SIZE);
         continue;
      }

      for (int j = 0; j < payload_list_len; ++j) {
         fp_dbg("Getting enrollment data for payload_id:");
         fp_dbg_large_hex(payload_list[j], DB2_ID_SIZE);
         BOOL_CHECK(get_enrollment_data(self, payload_list[j],
                                        &((*enrollments)[*enrollments_cnt]),
                                        error));
         *enrollments_cnt += 1;

         if (*enrollments_cnt >= allocated_enrollments_cnt) {
            allocated_enrollments_cnt *= 2;
            *enrollments = g_realloc_n(*enrollments, allocated_enrollments_cnt,
                                       sizeof(enrollment_t));
         }
      }
      if (payload_list != NULL) {
         g_free(payload_list);
         payload_list = NULL;
      }
   }

error:
   if (!ret && (*enrollments != NULL)) {
      g_free(*enrollments);
      *enrollments = NULL;
   }
   return ret;
}

static FpPrint *fp_print_from_enrollment(FpiDeviceSynaTudorMoc *self,
                                         enrollment_t *enrollment)
{
   FpPrint *print;
   g_autofree gchar *user_id =
       g_strndup((gchar *)enrollment->user_id, sizeof(user_id_t));

   print = fp_print_new(FP_DEVICE(self));

   GVariant *uid = g_variant_new_fixed_array(
       G_VARIANT_TYPE_BYTE, enrollment->user_id, sizeof(user_id_t), 1);
   GVariant *tid = g_variant_new_fixed_array(
       G_VARIANT_TYPE_BYTE, enrollment->template_id, DB2_ID_SIZE, 1);

   GVariant *data = g_variant_new("(y@ay@ay)", enrollment->finger_id, tid, uid);

   fpi_print_set_type(print, FPI_PRINT_RAW);
   fpi_print_set_device_stored(print, TRUE);
   g_object_set(print, "fpi-data", data, NULL);
   g_object_set(print, "description", user_id, NULL);
   fpi_print_fill_from_user_id(print, user_id);

   return print;
}

static gboolean get_template_id_from_print_data(GVariant *data,
                                                db2_id_t template_id,
                                                GError **error)
{
   gboolean ret = TRUE;

   g_autoptr(GVariant) user_id_var = NULL;
   g_autoptr(GVariant) tid_var = NULL;
   const guint8 *tid = NULL;

   g_return_val_if_fail(data != NULL, FALSE);

   if (!g_variant_check_format_string(data, "(y@ay@ay)", FALSE)) {
      *error =
          fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_INVALID,
                                   "Print data has invalid fpi-data format");
      ret = FALSE;
      goto error;
   }

   guint8 finger_id = 0;
   g_variant_get(data, "(y@ay@ay)", finger_id, &tid_var, &user_id_var);

   gsize tid_len = 0;
   tid = g_variant_get_fixed_array(tid_var, &tid_len, 1);
   if (tid_len != DB2_ID_SIZE) {
      *error = fpi_device_error_new_msg(
          FP_DEVICE_ERROR_DATA_INVALID,
          "Stored template id in print data has invalid size of %lu", tid_len);
      ret = FALSE;
      goto error;
   }

   memcpy(template_id, tid, DB2_ID_SIZE);

error:
   return ret;
}

/* open -------------------------------------------------------------------- */

static void syna_tudor_moc_open(FpDevice *device)
{
   fp_dbg("==================== open start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;
   gboolean usb_device_claimed = FALSE;
   /* debug check */
   g_assert(sizeof(cert_t) == 400);

   G_DEBUG_HERE();

   self->cancellable = g_cancellable_new();

   /* Claim usb interface */
   if (!g_usb_device_claim_interface(fpi_device_get_usb_device(device), 0, 0,
                                     &error)) {
      goto error;
   }
   usb_device_claimed = TRUE;

   g_usb_device_reset(fpi_device_get_usb_device(device), &error);

   /* If last session was not properly closed, sending any unencrypted command
    * will result in error */
   if (!handle_tls_statuses_for_sensor_and_host(self, &error)) {
      goto error;
   }

   /* get MiS version */
   if (!send_get_version(self, &self->mis_version, &error)) {
      goto error;
   }

   if (sensor_is_in_bootloader_mode(self)) {
      if (!exit_bootloader_mode(self, &error)) {
         goto error;
      }
   }

   guint8 provision_state = self->mis_version.provision_state & 0xF;
   gboolean is_provisioned = provision_state == PROVISION_STATE_PROVISIONED;
   if (is_provisioned) {
#ifdef STORAGE_ENABLED
      /* NOTE: this is not ideal as some errors should be handled differently */
      if (!host_partition_load_pairing_data(self, &error)) {
         fp_err("Unable to load pairing data");
         fp_dbg("Trying to pair");
         if (!pair(self, &error)) {
            fp_err("Unable to pair");
            goto error;
         }
      }
#else
      if (!load_sample_pairing_data(self, &error)) {
         fp_err("Error while loading sample pairing data");
         goto error;
      }
#endif

      /* pairing data should be present now */
      BUG_ON(!self->pairing_data.present);

      if (!verify_sensor_certificate(self, &error)) {
         error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
                                          "Sensor certificate is invalid");
         goto error;
      }

   } else {
      /* If sensor is not paired, then the sample pairing data will not work,
       * this is why this is not using STORAGE_ENABLED */
      fp_warn("Sensor is not paired");
      if (!pair(self, &error)) {
         goto error;
      }
   }

   if (!self->tls.established) {
      if (!establish_tls_session(self, &error)) {
         goto error;
      }
   }

#ifdef STORAGE_ENABLED
   if (!self->pairing_data.loaded_from_storage &&
       !host_partition_store_pairing_data(self, &error)) {
      fp_err("Unable to store pairing data");
      goto error;
   }
#endif

error:
   if (error != NULL && usb_device_claimed) {
      g_usb_device_release_interface(fpi_device_get_usb_device(device), 0, 0,
                                     NULL);
   }

   fpi_device_open_complete(FP_DEVICE(self), error);
}

/* close --------------------------------------------------------------------*/

static void syna_tudor_moc_close(FpDevice *device)
{
   fp_dbg("==================== close start ====================");

   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   G_DEBUG_HERE();

   g_autoptr(GError) release_error = NULL;

   g_clear_object(&self->cancellable);

   if (self->tls.established) {
      tls_close_session(self, &error);
   }

   deinit_tls(self);
   free_pairing_data(self);

   g_usb_device_release_interface(fpi_device_get_usb_device(FP_DEVICE(self)), 0,
                                  0, &release_error);

   fpi_device_close_complete(device, release_error);
}

/* enroll -------------------------------------------------------------------*/

static void syna_tudor_moc_enroll(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   guint16 finger_id;
   GError *error = NULL;
   GError *retry_error = NULL;

   G_DEBUG_HERE();

   FpPrint *print = NULL;
   fpi_device_get_enroll_data(device, &print);

   user_id_t user_id = {0};
   g_autofree char *user_id_str = fpi_print_generate_user_id(print);
   gsize user_id_str_len = strlen(user_id_str);
   memcpy(user_id, user_id_str, user_id_str_len);

   finger_id = fp_print_get_finger(print);

   fp_dbg("Trying to enroll print with:");
   fp_dbg("\tuser_id:");
   fp_dbg_large_hex(user_id, sizeof(user_id_t));
   fp_dbg("\tfinger_id/sub_id: %u", finger_id);

   if (!send_enroll_start(self, &error)) {
      goto error;
   }

   /* TODO: shoud be checked if finger_id is already enrolled? */

   enroll_add_image_t enroll_stats = {0};
   while (enroll_stats.progress != 100) {
      if (!send_event_config(self, EV_FINGER_UP, &error)) {
         goto error;
      }

      if (!wait_for_events_blocking(self, EV_FINGER_UP, &error)) {
         fp_err("wait_for_events_blocking failed");
         goto error;
      }

      if (!capture_image(self, CAPTURE_FLAGS_ENROLL, &error)) {
         fp_err("capture image failed");
         goto error;
      }

      if (!send_enroll_add_image(self, &enroll_stats, &error)) {
         fp_err("enroll add image failed");
         goto error;
      }

      if (enroll_stats.status != 0) {
         fp_err("status %d != 0", enroll_stats.status);
         goto error;
      }

      if (enroll_stats.rejected != 0) {
         if (enroll_stats.redundant != 0) {
            fp_info("Image rejected due to being redundant: %u",
                    enroll_stats.redundant);
            retry_error = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                                   "Scan is redundant");
         } else {
            fp_info("Image rejected due to bad quality: %u%%",
                    enroll_stats.quality);
            retry_error = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                                   "Scan has bad quality");
         }
         fpi_device_enroll_progress(device, enroll_stats.template_cnt, NULL,
                                    retry_error);
      } else {
         fp_info("Image accepted with quality: %u%%", enroll_stats.quality);
         fpi_device_enroll_progress(device, enroll_stats.template_cnt, NULL,
                                    NULL);
      }
   }

   g_assert(enroll_stats.progress == 100);
   fp_info("Enrollment finished with quality %u", enroll_stats.enroll_quality);
   fp_dbg("Template ID is:");
   fp_dbg_large_hex(enroll_stats.template_id, DB2_ID_SIZE);

   if (!add_enrollment(self, user_id, finger_id, enroll_stats.template_id,
                       &error)) {
      fp_err("Adding enrollment failed");
      goto error;
   }

   if (!send_enroll_finish(self, &error)) {
      fp_err("Sending enroll finish failed");
      goto error;
   }

   GVariant *uid = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, user_id,
                                             sizeof(user_id_t), 1);
   GVariant *tid = g_variant_new_fixed_array(
       G_VARIANT_TYPE_BYTE, enroll_stats.template_id, DB2_ID_SIZE, 1);
   GVariant *data = g_variant_new("(y@ay@ay)", finger_id, tid, uid);
   fpi_print_set_type(print, FPI_PRINT_RAW);
   fpi_print_set_device_stored(print, TRUE);
   g_object_set(print, "fpi-data", data, NULL);
   g_object_set(print, "description", user_id, NULL);

   fpi_device_enroll_complete(device, g_object_ref(print), NULL);
   return;

error:
   if (!send_enroll_finish(self, &error)) {
      fp_err("Sending enroll (finish) cancel failed");
   }
   fpi_device_enroll_complete(device, NULL, error);
}

/* verify ------------------------------------------------------------------ */

static void syna_tudor_moc_verify(FpDevice *device)
{
   fp_dbg("==================== verify start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;
   FpPrint *print_to_verify = NULL;
   g_autoptr(GVariant) fp_data = NULL;

   G_DEBUG_HERE();

   if (!capture_image(self, CAPTURE_FLAGS_AUTH, &error)) {
      goto error;
   }

   guint32 image_quality = 0;
   if (!send_get_image_metrics(self, MIS_IMAGE_METRICS_IMG_QUALITY,
                               &image_quality, &error)) {
      goto error;
   }
   if (image_quality < IMAGE_QUALITY_THRESHOLD) {
      fp_info("Image quality %d%% is lower than threshold %d%%", image_quality,
              IMAGE_QUALITY_THRESHOLD);
      error = fpi_device_error_new_msg(
          FP_DEVICE_ERROR_GENERAL,
          "Image quality %d%% is lower than threshold %d%%", image_quality,
          IMAGE_QUALITY_THRESHOLD);
      goto error;
   }

   fpi_device_get_verify_data(device, &print_to_verify);
   g_object_get(print_to_verify, "fpi-data", &fp_data, NULL);

   db2_id_t template_id;
   if (!get_template_id_from_print_data(fp_data, template_id, &error)) {
      goto error;
   }

   gboolean matched = FALSE;
   enrollment_t enrollment_match = {0};
   if (!send_identify_match(self, NULL, 0, &matched, &enrollment_match,
                            &error)) {
      goto error;
   }
   fp_dbg("Identify matched: %d", matched);

   if (matched) {
      fp_dbg("Identify cmd matched enrollment with data:");
      fp_dbg("\tuser_id");
      fp_dbg_large_hex(enrollment_match.user_id, sizeof(user_id_t));
      fp_dbg("\ttemplate_id");
      fp_dbg_large_hex(enrollment_match.template_id, DB2_ID_SIZE);
      fp_dbg("\tfinger_id: %d", enrollment_match.finger_id);

      FpPrint *new_scan = fp_print_from_enrollment(self, &enrollment_match);
      fpi_device_verify_report(device, FPI_MATCH_SUCCESS, new_scan, error);
   } else {
      /* we get no print data on no match */
      fpi_device_verify_report(device, FPI_MATCH_FAIL, NULL, NULL);
   }

error:
   fpi_device_verify_complete(device, NULL);
}

/* identify ---------------------------------------------------------------- */

static void syna_tudor_moc_identify(FpDevice *device)
{
   fp_dbg("==================== identify start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   G_DEBUG_HERE();

   if (!capture_image(self, CAPTURE_FLAGS_AUTH, &error)) {
      goto error;
   }

   guint32 image_quality = 0;
   if (!send_get_image_metrics(self, MIS_IMAGE_METRICS_IMG_QUALITY,
                               &image_quality, &error)) {
      goto error;
   }
   if (image_quality < IMAGE_QUALITY_THRESHOLD) {
      fp_info("Image quality %d%% is lower than threshold %d%%", image_quality,
              IMAGE_QUALITY_THRESHOLD);
      error = fpi_device_error_new_msg(
          FP_DEVICE_ERROR_GENERAL,
          "Image quality %d%% is lower than threshold %d%%", image_quality,
          IMAGE_QUALITY_THRESHOLD);
      goto error;
   }

   gboolean matched = FALSE;
   enrollment_t enrollment_match = {0};
   if (!send_identify_match(self, NULL, 0, &matched, &enrollment_match,
                            &error)) {
      goto error;
   }
   fp_dbg("Identify matched: %d", matched);

   if (matched) {
      FpPrint *matching = NULL;
      FpPrint *new_scan = fp_print_from_enrollment(self, &enrollment_match);

      fp_dbg("Identify cmd matched enrollment with data:");
      fp_dbg("\tuser_id");
      fp_dbg_large_hex(enrollment_match.user_id, sizeof(user_id_t));
      fp_dbg("\ttemplate_id");
      fp_dbg_large_hex(enrollment_match.template_id, DB2_ID_SIZE);
      fp_dbg("\tfinger_id: %d", enrollment_match.finger_id);

      GPtrArray *templates = NULL;
      fpi_device_get_identify_data(device, &templates);
      for (gint i = 0; i < templates->len; ++i) {
         if (fp_print_equal(g_ptr_array_index(templates, i), new_scan)) {
            matching = g_ptr_array_index(templates, i);
            break;
         }
      }
      fpi_device_identify_report(device, matching, new_scan, NULL);
   } else {
      /* we get no print data on no match */
      fpi_device_identify_report(device, NULL, NULL, NULL);
   }

error:
   fpi_device_identify_complete(device, error);
}

/* list -------------------------------------------------------------------- */

static void syna_tudor_moc_list(FpDevice *device)
{
   fp_dbg("==================== list start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   guint enrollment_cnt = 0;
   g_autofree enrollment_t *enrollment_array;
   if (!get_enrollments(self, &enrollment_array, &enrollment_cnt, &error)) {
      fp_info("Unable to get database data");
      fpi_device_list_complete(device, NULL, error);
   }

   if (enrollment_cnt == 0) {
      fpi_device_list_complete(
          device, NULL,
          fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_FULL,
                                   "Database is empty"));
   }

   g_autoptr(GPtrArray) list_result = NULL;
   list_result = g_ptr_array_new_with_free_func(g_object_unref);

   for (int i = 0; i < enrollment_cnt; ++i) {
      FpPrint *print = fp_print_from_enrollment(self, &enrollment_array[i]);
      g_ptr_array_add(list_result, g_object_ref_sink(print));
   }

   fp_info("Query templates complete!");
   fpi_device_list_complete(device, g_steal_pointer(&list_result), NULL);
}

/* delete_print ------------------------------------------------------------ */

static void syna_tudor_moc_delete_print(FpDevice *device)
{
   fp_dbg("==================== delete start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   FpPrint *print;
   fpi_device_get_delete_data(device, &print);

   g_autoptr(GVariant) data = NULL;
   g_object_get(print, "fpi-data", &data, NULL);

   db2_id_t template_id;
   if (!get_template_id_from_print_data(data, template_id, &error)) {
      fpi_device_delete_complete(
          device, fpi_device_error_new_msg(
                      FP_DEVICE_ERROR_DATA_INVALID,
                      "Unable to get template id from print fpi-data"));
      return;
   }

   fp_dbg("Deleting print with template ID:");
   fp_dbg_large_hex(template_id, DB2_ID_SIZE);

   if (!send_db2_delete_object(self, OBJ_TYPE_TEMPLATES, &template_id,
                               &error)) {
      fpi_device_delete_complete(device, error);
   }

   fpi_device_delete_complete(device, NULL);
}

/* clear_storage ----------------------------------------------------------- */

static void syna_tudor_moc_clear_storage(FpDevice *device)
{
   fp_dbg("==================== clear storage start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   if (!send_db2_format(self, &error)) {
      goto error;
   }

error:
   fpi_device_clear_storage_complete(device, error);
}

/* cancel ------------------------------------------------------------------ */

/* static void syna_tudor_moc_cancel(FpDevice *device)
{
   fp_dbg("==================== cancel start ====================");
} */

/* suspend ----------------------------------------------------------------- */

/* static void syna_tudor_moc_suspend(FpDevice *device)
{
   fp_dbg("==================== suspend start ====================");
} */

/* resume ------------------------------------------------------------------ */

/* static void syna_tudor_moc_resume(FpDevice *device)
{
   fp_dbg("==================== resume start ====================");
} */

/* ------------------------------------------------------------------------- */

static void fpi_device_syna_tudor_moc_init(FpiDeviceSynaTudorMoc *self)
{
   G_DEBUG_HERE();
}

static void
fpi_device_syna_tudor_moc_class_init(FpiDeviceSynaTudorMocClass *klass)
{
   FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

   dev_class->id = FP_COMPONENT;
   dev_class->full_name = SYNA_TUDOR_MOC_DRIVER_FULLNAME;

   dev_class->type = FP_DEVICE_TYPE_USB;
   dev_class->id_table = id_table;
   dev_class->nr_enroll_stages = SYNA_TUDOR_MOC_DRIVER_NR_ENROLL_STAGES;
   dev_class->scan_type = FP_SCAN_TYPE_PRESS;

   dev_class->temp_hot_seconds = -1;
   dev_class->temp_cold_seconds = -1;

   /* dev_class->usb_discover */
   /* dev_class->probe */
   dev_class->open = syna_tudor_moc_open;
   dev_class->close = syna_tudor_moc_close;
   dev_class->enroll = syna_tudor_moc_enroll;
   dev_class->verify = syna_tudor_moc_verify;
   dev_class->identify = syna_tudor_moc_identify;
   /* dev_class->capture */
   dev_class->list = syna_tudor_moc_list;
   dev_class->delete = syna_tudor_moc_delete_print;
   dev_class->clear_storage = syna_tudor_moc_clear_storage;
   /* dev_class->cancel = syna_tudor_moc_cancel; */
   /* dev_class->suspend = syna_tudor_moc_suspend; */
   /* dev_class->resume = syna_tudor_moc_resume; */

   fpi_device_class_auto_initialize_features(dev_class);
}
