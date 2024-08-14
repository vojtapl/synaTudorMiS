/*
 * TODO: add header
 */

#include "communication.c"
#include "communication.h"
#include "device.h"
#include "drivers_api.h"
#include "syna_tudor_moc.h"
#include "tls.c"
#include "tls.h"

static db2_id_t cache_tuid = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

G_DEFINE_TYPE(FpiDeviceSynaTudorMoc, fpi_device_syna_tudor_moc, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
    // only 00FF is tested
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00C9, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00D1, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00E7, },
    {
        .vid = SYNAPTICS_VENDOR_ID,
        .pid = 0x00FF,
    },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0124, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0169, },
    {.vid = 0, .pid = 0, .driver_data = 0}, /* terminating entry */
};

static gboolean capture_image(FpiDeviceSynaTudorMoc *self, guint8 frame_flags,
                              GError *error)
{
   gboolean ret = TRUE;

   fp_dbg("setting event config to EV_FRAME_READY");
   BOOL_CHECK(send_event_config(self, EV_FRAME_READY, error));

   BOOL_CHECK(send_frame_acq(self, frame_flags, error));

   fpi_device_report_finger_status(FP_DEVICE(self), FP_FINGER_STATUS_NEEDED);
   fp_dbg("setting event config to EV_FRAME_READY | EV_FINGER_DOWN");
   BOOL_CHECK(send_event_config(self, EV_FRAME_READY | EV_FINGER_DOWN, error));

   BOOL_CHECK(
       wait_for_events_blocking(self, EV_FRAME_READY | EV_FINGER_DOWN, error));

   fpi_device_report_finger_status(FP_DEVICE(self), FP_FINGER_STATUS_PRESENT);

   BOOL_CHECK(send_event_config(self, 0, error));

   BOOL_CHECK(send_frame_finish(self, error));

error:
   return ret;
}

static gboolean get_enrollment_data(FpiDeviceSynaTudorMoc *self,
                                    db2_id_t payload_id,
                                    enrollment_t *enrollment, GError *error)
{
   gboolean ret = TRUE;

   guint obj_data_size;
   g_autofree guint8 *obj_data;
   BOOL_CHECK(send_db2_get_object_data(self, OBJ_TYPE_PAYLOADS, payload_id,
                                       &obj_data, &obj_data_size, error));

   BOOL_CHECK(get_enrollment_data_from_serialized_container(
       obj_data, obj_data_size, enrollment));

error:
   return ret;
}

static gboolean get_enrollments(FpiDeviceSynaTudorMoc *self,
                                enrollment_t **enrollments,
                                guint *enrollments_cnt, GError *error)
{
   gboolean ret = TRUE;

   guint allocated_enrollments_cnt = 5;
   *enrollments = g_malloc_n(allocated_enrollments_cnt, sizeof(enrollment_t));

   guint16 tuid_list_len = 0;
   g_autofree db2_id_t *tuid_list = NULL;
   g_autofree db2_id_t *payload_list = NULL;

   BOOL_CHECK(send_db2_get_object_list(self, OBJ_TYPE_TEMPLATES, cache_tuid,
                                       &tuid_list, &tuid_list_len, error));
   if (tuid_list_len == 0) {
      fp_dbg("received empty tuid_list");
      goto error;
   }

   for (int i = 0; i < tuid_list_len; ++i) {
      guint16 payload_list_len = 0;
      fp_dbg("Getting payloads for template_id:");
      print_array(tuid_list[i], sizeof(db2_id_t));
      BOOL_CHECK(send_db2_get_object_list(self, OBJ_TYPE_PAYLOADS, tuid_list[i],
                                          &payload_list, &payload_list_len,
                                          error));
      if (payload_list_len == 0) {
         fp_warn("No payload data for enrollment with tuid:");
         print_array(tuid_list[i], sizeof(db2_id_t));
         continue;
      }

      for (int j = 0; j < payload_list_len; ++j) {
         fp_dbg("Getting enrollment data for payload_id:");
         print_array(payload_list[j], sizeof(db2_id_t));
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
       G_VARIANT_TYPE_BYTE, enrollment->template_id, sizeof(db2_id_t), 1);

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
                                                GError *error)
{
   gboolean ret = TRUE;

   g_autoptr(GVariant) user_id_var = NULL;
   g_autoptr(GVariant) tid_var = NULL;
   g_autofree const guint8 *tid = NULL;

   g_return_val_if_fail(data != NULL, FALSE);

   if (!g_variant_check_format_string(data, "(y@ay@ay)", FALSE)) {
      error =
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
      error = fpi_device_error_new_msg(
          FP_DEVICE_ERROR_DATA_INVALID,
          "Stored template id in print data has invalid size of %lu", tid_len);
      ret = FALSE;
      goto error;
   }

   memcpy(template_id, tid, DB2_ID_SIZE);

error:
   return ret;
}

// open -----------------------------------------------------------------------

static void syna_tudor_moc_open(FpDevice *device)
{
   fp_dbg("==================== open start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   G_DEBUG_HERE();

   self->interrupt_cancellable = g_cancellable_new();

   /* Claim usb interface */
   if (!g_usb_device_claim_interface(fpi_device_get_usb_device(device), 0, 0,
                                     &error)) {
      goto error;
   }

   g_usb_device_reset(fpi_device_get_usb_device(device), &error);

   get_version_t version_data = {0};
   if (!send_get_version(self, &version_data, error)) {
      goto error;
   }

   gboolean in_bootloader_mode =
       version_data.product_id == 'B' || version_data.product_id == 'C';
   if (in_bootloader_mode) {
      fp_err("Sensor is in bootloader mode!");
      g_assert(FALSE);
   }

   guint8 provision_state = version_data.provision_state & 0xF;
   gboolean is_provisioned = provision_state == PROVISION_STATE_PROVISIONED;
   if (is_provisioned) {
      if (!load_sample_pairing_data(self)) {
         fp_err("Error while loading sample pairing data");
         goto error;
      }

      if (!self->pairing_data.present) {
         fp_err("No present pairing_data - need to pair / read from storage!");
         fp_err("\t-> Not implemented");
         g_assert(FALSE);
      }

      // TODO:
      // if (!verify_sensor_certificate(self)) {

   } else {
      fp_err("Sensor is not paired");
      fp_err("\t-> Not implemented");
      g_assert(FALSE);
   }

   g_assert(!self->task_ssm);

   establish_tls_session(self, error);

   gboolean tls_status = FALSE;
   get_remote_tls_status(self, &tls_status, error);
   fp_dbg("remote TLS status before sending: %d", tls_status);

   get_version_t version_data2 = {0};
   if (!send_get_version(self, &version_data2, error)) {
      goto error;
   }
   tls_status = FALSE;
   get_remote_tls_status(self, &tls_status, error);
   fp_dbg("remote TLS status after sending: %d", tls_status);

error:
   fpi_device_open_complete(FP_DEVICE(self), error);
}

// close ----------------------------------------------------------------------

static void syna_tudor_moc_close(FpDevice *device)
{
   fp_dbg("==================== close start ====================");

   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   G_DEBUG_HERE();

   g_autoptr(GError) release_error = NULL;

   g_clear_object(&self->interrupt_cancellable);

   if (self->tls.established) {
      tls_close_session(self, error);
   }
   if (self->tls.master_secret.data != NULL) {
      g_free(self->tls.master_secret.data);
   }
   if (self->tls.encryption_key.data != NULL) {
      g_free(self->tls.encryption_key.data);
   }
   if (self->tls.decryption_key.data != NULL) {
      g_free(self->tls.decryption_key.data);
   }
   if (self->tls.encryption_iv.data != NULL) {
      g_free(self->tls.encryption_iv.data);
   }
   if (self->tls.decryption_iv.data != NULL) {
      g_free(self->tls.decryption_iv.data);
   }
   if (self->tls.session_id != NULL) {
      g_free(self->tls.session_id);
   }
   if (self->pairing_data.sensor_cert.sign_data != NULL) {
      g_free(self->pairing_data.sensor_cert.sign_data);
   }
   if (self->pairing_data.host_cert.sign_data != NULL) {
      g_free(self->pairing_data.host_cert.sign_data);
   }
   gnutls_privkey_deinit(self->pairing_data.private_key);

   g_usb_device_release_interface(fpi_device_get_usb_device(FP_DEVICE(self)), 0,
                                  0, &release_error);

   fpi_device_close_complete(device, release_error);
}

// enroll ---------------------------------------------------------------------

static void syna_tudor_moc_enroll(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   guint16 finger_id;
   GError error;

   G_DEBUG_HERE();

   FpPrint *print = NULL;
   fpi_device_get_enroll_data(device, &print);

   user_id_t user_id = {0};
   g_autofree char *user_id_str = fpi_print_generate_user_id(print);
   gsize user_id_str_len = strlen(user_id_str);
   memcpy(user_id, user_id_str, user_id_str_len);

   // get finger id
   finger_id = fp_print_get_finger(print);

   fp_dbg("Trying to enroll print with:");
   fp_dbg("\tuser_id:");
   print_array(user_id, sizeof(user_id_t));
   fp_dbg("\tfinger_id/sub_id: %u", finger_id);

   if (!send_enroll_start(self, &error)) {
      goto error;
   }

   // TODO: check if finger_id is already enrolled

   enroll_add_image_t enroll_stats = {0};
   while (enroll_stats.progress != 100) {
      if (!send_event_config(self, EV_FINGER_UP, &error)) {
         goto error;
      }

      wait_for_events_blocking(self, EV_FINGER_UP, &error);

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
         } else {
            fp_info("Image rejected due to bad quality: %u%%",
                    enroll_stats.quality);
         }
      } else {
         fp_info("Image accepted with quality: %u%%", enroll_stats.quality);
      }
   }

   g_assert(enroll_stats.progress == 100);
   fp_info("Enrollment finished with quality %u", enroll_stats.enroll_quality);
   fp_dbg("Template ID is:");
   print_array(enroll_stats.tuid, sizeof(db2_id_t));

   if (!add_enrollment(self, user_id, finger_id, enroll_stats.tuid, &error)) {
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
       G_VARIANT_TYPE_BYTE, enroll_stats.tuid, sizeof(db2_id_t), 1);
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
   fpi_device_enroll_complete(device, NULL, &error);
}

// verify ---------------------------------------------------------------------

static void fp_verify_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
}

static void fp_verify_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(dev);
   fp_info("verify complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_verify_complete(dev, error);
   self->task_ssm = NULL;
}

static void syna_tudor_moc_verify(FpDevice *device)
{
   fp_dbg("==================== verify start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;
   FpPrint *print_to_verify = NULL;
   g_autoptr(GVariant) fp_data;

   G_DEBUG_HERE();

   if (!capture_image(self, CAPTURE_FLAGS_AUTH, error)) {
      goto error;
   }

   guint32 image_quality = 0;
   if (!send_get_image_metrics(self, MIS_IMAGE_METRICS_IMG_QUALITY,
                               &image_quality, error)) {
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
   if (!get_template_id_from_print_data(fp_data, template_id, error)) {
      goto error;
   }

   gboolean matched = FALSE;
   enrollment_t enrollment_match = {0};
   if (!send_identify_match(self, NULL, 0, &matched, &enrollment_match,
                            error)) {
      goto error;
   }
   fp_dbg("Identify matched: %d", matched);

   if (matched) {
      FpPrint *new_scan = fp_print_from_enrollment(self, &enrollment_match);
      fpi_device_verify_report(device, FPI_MATCH_SUCCESS, new_scan, error);

      fp_dbg("Identify cmd matched enrollment with data:");
      fp_dbg("\tuser_id");
      print_array(enrollment_match.user_id, sizeof(user_id_t));
      fp_dbg("\ttemplate_id");
      print_array(enrollment_match.template_id, sizeof(db2_id_t));
      fp_dbg("\tfinger_id: %d", enrollment_match.finger_id);

   } else {
      // we get no print data on no match
      fpi_device_verify_report(device, FPI_MATCH_FAIL, NULL, NULL);
   }

error:
   fpi_device_verify_complete(device, error);
}

// identify -------------------------------------------------------------------

static void syna_tudor_moc_identify(FpDevice *device)
{
   fp_dbg("==================== identify start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;

   G_DEBUG_HERE();

   if (!capture_image(self, CAPTURE_FLAGS_AUTH, error)) {
      goto error;
   }

   guint32 image_quality = 0;
   if (!send_get_image_metrics(self, MIS_IMAGE_METRICS_IMG_QUALITY,
                               &image_quality, error)) {
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
                            error)) {
      goto error;
   }
   fp_dbg("Identify matched: %d", matched);

   if (matched) {
      FpPrint *matching = NULL;
      FpPrint *new_scan = fp_print_from_enrollment(self, &enrollment_match);

      fp_dbg("Identify cmd matched enrollment with data:");
      fp_dbg("\tuser_id");
      print_array(enrollment_match.user_id, sizeof(user_id_t));
      fp_dbg("\ttemplate_id");
      print_array(enrollment_match.template_id, sizeof(db2_id_t));
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
      // we get no print data on no match
      fpi_device_identify_report(device, NULL, NULL, NULL);
   }

error:
   fpi_device_identify_complete(device, error);
}

// list -----------------------------------------------------------------------

static void syna_tudor_moc_list(FpDevice *device)
{
   fp_dbg("==================== list start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError error;

   guint enrollment_cnt = 0;
   g_autofree enrollment_t *enrollment_array;
   if (!get_enrollments(self, &enrollment_array, &enrollment_cnt, &error)) {
      fp_info("Unable to get database data");
      fpi_device_list_complete(device, NULL, &error);
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

// delete_print ---------------------------------------------------------------

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
   if (!get_template_id_from_print_data(data, template_id, error)) {
      fpi_device_delete_complete(
          device, fpi_device_error_new_msg(
                      FP_DEVICE_ERROR_DATA_INVALID,
                      "Unable to get template id from print fpi-data"));
      return;
   }

   fp_dbg("Deleting print with template ID:");
   print_array(template_id, DB2_ID_SIZE);

   fp_warn("TEST5");

   if (!send_db2_delete_object(self, OBJ_TYPE_TEMPLATES, &template_id, error)) {
      fpi_device_delete_complete(device, error);
   }

   fpi_device_delete_complete(device, NULL);
}

// clear_storage --------------------------------------------------------------

static void syna_tudor_moc_clear_storage(FpDevice *device)
{
   fp_dbg("==================== clear storage start ====================");
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError error;

   if (!send_db2_format(self, &error)) {
      goto error;
   }

error:
   // FIXME:
   // fpi_device_clear_storage_complete(device, &error);
   fpi_device_clear_storage_complete(device, NULL);
}

// cancel ---------------------------------------------------------------------

static void fp_cancel_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
}

static void fp_cancel_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(dev);
   fp_info("cancel complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   self->task_ssm = NULL;
}

static void syna_tudor_moc_cancel(FpDevice *device)
{
   fp_dbg("==================== cancel start ====================");
}

// suspend --------------------------------------------------------------------

static void syna_tudor_moc_suspend(FpDevice *device)
{
   fp_dbg("==================== suspend start ====================");
}

// resume ---------------------------------------------------------------------

static void syna_tudor_moc_resume(FpDevice *device)
{
   fp_dbg("==================== resume start ====================");
}

// ----------------------------------------------------------------------------

static void fpi_device_syna_tudor_moc_init(FpiDeviceSynaTudorMoc *self)
{
   fp_dbg("==================== init start ====================");
}

static void
fpi_device_syna_tudor_moc_class_init(FpiDeviceSynaTudorMocClass *klass)
{
   FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

   dev_class->id = FP_COMPONENT;
   dev_class->full_name = SYNA_TUDOR_MOC_DRIVER_FULLNAME;

   dev_class->type = FP_DEVICE_TYPE_USB;
   dev_class->id_table = id_table;
   // TODO: features
   dev_class->nr_enroll_stages = SYNA_TUDOR_MOC_DRIVER_NR_ENROLL_STAGES;
   dev_class->scan_type = FP_SCAN_TYPE_PRESS;

   // TODO: set these numbers correctly
   dev_class->temp_hot_seconds = -1;
   dev_class->temp_cold_seconds = -1;

   // dev_class->usb_discover
   // dev_class->probe
   dev_class->open = syna_tudor_moc_open;
   dev_class->close = syna_tudor_moc_close;
   dev_class->enroll = syna_tudor_moc_enroll;
   dev_class->verify = syna_tudor_moc_verify;
   dev_class->identify = syna_tudor_moc_identify;
   // dev_class->capture
   dev_class->list = syna_tudor_moc_list;
   dev_class->delete = syna_tudor_moc_delete_print;
   dev_class->clear_storage = syna_tudor_moc_clear_storage;
   // dev_class->cancel = syna_tudor_moc_cancel;
   // dev_class->suspend = syna_tudor_moc_suspend;
   // dev_class->resume = syna_tudor_moc_resume;

   fpi_device_class_auto_initialize_features(dev_class);
}
