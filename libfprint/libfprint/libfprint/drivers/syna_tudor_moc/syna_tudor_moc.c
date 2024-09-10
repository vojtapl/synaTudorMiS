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

/* WARNING: current implementation starts a new TLS session on each device open
 */

#include "communication.c"
#include "device.h"
#include "fpi-log.h"
#include "fpi-ssm.h"
#include "syna_tudor_moc.h"
#include "tls.c"
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

/* Needed for testing with libfprint examples they do not support storage of
 * pairing data */
#define USE_SAMPLE_PAIRING_DATA

static db2_id_t cache_template_id = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff};

G_DEFINE_TYPE(FpiDeviceSynaTudorMoc, fpi_device_syna_tudor_moc, FP_TYPE_DEVICE)

// clang-format off
static const FpIdEntry id_table[] = {
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00C9, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00D1, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00E7, },
    /* only 00FF is tested */
    { .vid = SYNAPTICS_VENDOR_ID, .pid = 0x00FF, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0124, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0169, },
    {.vid = 0, .pid = 0, .driver_data = 0}, /* terminating entry */
};
// clang-format on

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
      *error = set_and_report_error(FP_DEVICE_ERROR_DATA_INVALID,
                                    "Print data has invalid fpi-data format");
      ret = FALSE;
      goto error;
   }

   guint8 finger_id = 0;
   g_variant_get(data, "(y@ay@ay)", finger_id, &tid_var, &user_id_var);

   gsize tid_len = 0;
   tid = g_variant_get_fixed_array(tid_var, &tid_len, 1);
   if (tid_len != DB2_ID_SIZE) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_DATA_INVALID,
          "Stored template id in print data has invalid size of %lu", tid_len);
      ret = FALSE;
      goto error;
   }

   memcpy(template_id, tid, DB2_ID_SIZE);

error:
   return ret;
}

static gboolean store_pairing_data(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   if (!self->pairing_data.present) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Unable to store pairing data if they are not present");
      ret = FALSE;
      goto error;
   }

   GVariant *host_cert = g_variant_new_fixed_array(
       G_VARIANT_TYPE_BYTE, &self->pairing_data.host_cert, CERTIFICATE_SIZE, 1);
   GVariant *sensor_cert = g_variant_new_fixed_array(
       G_VARIANT_TYPE_BYTE, &self->pairing_data.sensor_cert, CERTIFICATE_SIZE,
       1);

   gnutls_datum_t x = {.data = NULL};
   gnutls_datum_t y = {.data = NULL};
   gnutls_datum_t k = {.data = NULL};
   gnutls_ecc_curve_t curve;
   /* as we use only one curve, there is no need to store it */
   GNUTLS_CHECK(gnutls_privkey_export_ecc_raw2(self->pairing_data.private_key,
                                               &curve, &x, &y, &k,
                                               GNUTLS_EXPORT_FLAG_NO_LZ));

   GVariant *private_key_x_var =
       g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, x.data, x.size, 1);
   GVariant *private_key_y_var =
       g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, y.data, y.size, 1);
   GVariant *private_key_k_var =
       g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, k.data, k.size, 1);

   GVariant *pairing_data =
       g_variant_new("(@ay@ayu@ay@ay@ay)", host_cert, sensor_cert, curve,
                     private_key_x_var, private_key_y_var, private_key_k_var);

   g_object_set(FP_DEVICE(self), "fpi-persistent-data", pairing_data, NULL);

   fp_dbg("Pairing data store success");

   fp_dbg("Pairing data:");
   fp_dbg("\tSensor certificate:");
   fp_dbg_large_hex((guint8 *)&self->pairing_data.sensor_cert,
                    CERTIFICATE_SIZE);
   fp_dbg("\tHost certificate:");
   fp_dbg_large_hex((guint8 *)&self->pairing_data.host_cert, CERTIFICATE_SIZE);
   fp_dbg("\tPrivate key x:");
   fp_dbg_large_hex(x.data, x.size);
   fp_dbg("\tPrivate key y:");
   fp_dbg_large_hex(y.data, y.size);
   fp_dbg("\tPrivate key k:");
   fp_dbg_large_hex(k.data, k.size);

error:
   if (x.data != NULL) {
      g_free(x.data);
   }
   if (y.data != NULL) {
      g_free(y.data);
   }
   if (k.data != NULL) {
      g_free(k.data);
   }
   return ret;
}

static gboolean load_pairing_data(FpiDeviceSynaTudorMoc *self, GError **error)
{
   gboolean ret = TRUE;

   if (self->pairing_data.present) {
      fp_warn("Overwriting currently stored pairing data");
      self->pairing_data.present = FALSE;
      if (self->pairing_data.private_key_initialized) {
         gnutls_privkey_deinit(self->pairing_data.private_key);
         self->pairing_data.private_key_initialized = FALSE;
      }
   }

   g_autoptr(GVariant) pairing_data = NULL;
   g_autoptr(GVariant) sensor_cert_var = NULL;
   g_autoptr(GVariant) host_cert_var = NULL;
   g_autoptr(GVariant) private_key_x_var = NULL;
   g_autoptr(GVariant) private_key_y_var = NULL;
   g_autoptr(GVariant) private_key_k_var = NULL;
   gnutls_datum_t x = {.data = NULL};
   gnutls_datum_t y = {.data = NULL};
   gnutls_datum_t k = {.data = NULL};
   gnutls_ecc_curve_t curve = 0;

   g_object_get(FP_DEVICE(self), "fpi-persistent-data", &pairing_data, NULL);

   if (pairing_data == NULL) {
      *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "Received NULL as stored pairing data");
      ret = FALSE;
      goto error;
   }

   if (!g_variant_check_format_string(pairing_data, "(@ay@ayu@ay@ay@ay)",
                                      FALSE)) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL, "Stored pairing data have incorrect format");
      ret = FALSE;
      goto error;
   }

   g_variant_get(pairing_data, "(@ay@ayu@ay@ay@ay)", &host_cert_var,
                 &sensor_cert_var, &curve, &private_key_x_var,
                 &private_key_y_var, &private_key_k_var);

   gsize host_cert_data_size = 0;
   guint8 *host_cert_data = (guint8 *)g_variant_get_fixed_array(
       host_cert_var, &host_cert_data_size, 1);
   if (host_cert_data_size != CERTIFICATE_SIZE) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Stored host certificate has invalid size: %lu", host_cert_data_size);
      ret = FALSE;
      goto error;
   }
   memcpy(&self->pairing_data.host_cert, host_cert_data, CERTIFICATE_SIZE);

   gsize sensor_cert_data_size = 0;
   guint8 *sensor_cert_data = (guint8 *)g_variant_get_fixed_array(
       sensor_cert_var, &sensor_cert_data_size, 1);
   if (sensor_cert_data_size != CERTIFICATE_SIZE) {
      *error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Stored sensor certificate has invalid size: %lu",
          sensor_cert_data_size);
      ret = FALSE;
      goto error;
   }
   memcpy(&self->pairing_data.sensor_cert, sensor_cert_data, CERTIFICATE_SIZE);

   x.data = (guint8 *)g_variant_get_fixed_array(private_key_x_var,
                                                (gsize *)&x.size, 1);

   y.data = (guint8 *)g_variant_get_fixed_array(private_key_y_var,
                                                (gsize *)&y.size, 1);
   k.data = (guint8 *)g_variant_get_fixed_array(private_key_k_var,
                                                (gsize *)&k.size, 1);

   GNUTLS_CHECK(gnutls_privkey_init(&self->pairing_data.private_key));
   self->pairing_data.private_key_initialized = TRUE;

   /* as we use only one curve, there is no need to store it */
   GNUTLS_CHECK(gnutls_privkey_import_ecc_raw(self->pairing_data.private_key,
                                              curve, &x, &y, &k));
   GNUTLS_CHECK(gnutls_privkey_verify_params(self->pairing_data.private_key));
   self->pairing_data.private_key_initialized = TRUE;

   self->pairing_data.present = TRUE;

   fp_dbg("Pairing data load success");

   fp_dbg("Pairing data:");
   fp_dbg("\tSensor certificate:");
   fp_dbg_large_hex((guint8 *)&self->pairing_data.sensor_cert,
                    CERTIFICATE_SIZE);
   fp_dbg("\tHost certificate:");
   fp_dbg_large_hex((guint8 *)&self->pairing_data.host_cert, CERTIFICATE_SIZE);
   fp_dbg("\tPrivate key x:");
   fp_dbg_large_hex(x.data, x.size);
   fp_dbg("\tPrivate key y:");
   fp_dbg_large_hex(y.data, y.size);
   fp_dbg("\tPrivate key k:");
   fp_dbg_large_hex(k.data, k.size);

error:
   return ret;
}

/* open ==================================================================== */

static void fetch_pairing_data(FpiDeviceSynaTudorMoc *self)
{
   GError *error = NULL;

#ifdef USE_SAMPLE_PAIRING_DATA
   if (!load_sample_pairing_data(self, &error)) {
      fp_err("Error while loading sample pairing data");
      goto error;
   }
#else

   g_autoptr(GVariant) pairing_data = NULL;
   g_object_get(FP_DEVICE(self), "fpi-persistent-data", &pairing_data, NULL);

   guint8 provision_state = self->mis_version.provision_state & 0xF;
   gboolean need_to_pair = provision_state != PROVISION_STATE_PROVISIONED;

   if (need_to_pair || pairing_data == NULL) {
      if (pairing_data == NULL) {
         fp_warn("Previous pairing data in persistent storage are NULL");
      }

      fp_warn("Need to pair sensor");

      if (!pair(self, &error)) {
         goto error;
      }
      if (!store_pairing_data(self, &error)) {
         fp_err("Unable to store pairing data");
         goto error;
      }
   } else {
      if (!load_pairing_data(self, &error)) {
         fp_err("Unable to load pairing data");
         goto error;
      }
   }
#endif

   if (!self->pairing_data.present) {
      error = set_and_report_error(
          FP_DEVICE_ERROR_GENERAL,
          "Pairing data should have been loaded but are not");
      goto error;
   }

error:
   if (error != NULL) {
      fpi_ssm_mark_failed(self->task_ssm, error);
   }
   return;
}

static void open_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   open_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);
   GError *error = NULL;

   switch (fpi_ssm_get_cur_state(ssm)) {
   case OPEN_STATE_GET_REMOTE_TLS_STATUS:
      /* NOTE: If last session was not properly closed, sending any unencrypted
       * command will result in error */
      send_get_remote_tls_status(self);
      break;
   case OPEN_STATE_HANDLE_TLS_STATUSES:;
      gboolean remote_established =
          self->parsed_recv_data.sensor_is_in_tls_session;
      if (self->tls.established && !remote_established) {
         fp_warn("Host is in TLS session but sensor is not");
         self->tls.established = FALSE;
         fpi_ssm_jump_to_state(ssm, OPEN_STATE_SEND_GET_VERSION);
      } else if (!self->tls.established && remote_established) {
         fp_warn("Sensor is in TLS session but host is not");
         fpi_ssm_next_state(ssm);
      } else if (self->tls.established && remote_established) {
         fp_dbg("Host and sensor are already in TLS session");
         fpi_ssm_mark_completed(ssm);
      } else { // both not established
         fpi_ssm_jump_to_state(ssm, OPEN_STATE_SEND_GET_VERSION);
      }
      break;
   case OPEN_STATE_FORCE_CLOSE_SENSOR_TLS_SESSION:
      if (ssm_data->tried_to_close_tls_session) {
         fpi_ssm_mark_failed(
             ssm, set_and_report_error(
                      FP_DEVICE_ERROR_PROTO,
                      "Unable to get the sensor out of TLS session"));
      } else {
         send_cmd_to_force_close_sensor_tls_session(self);
      }
      break;
   case OPEN_STATE_CHECK_CLOSE_SUCCESS:
      fpi_ssm_jump_to_state(ssm, OPEN_STATE_GET_REMOTE_TLS_STATUS);
      break;
   case OPEN_STATE_SEND_GET_VERSION:
      send_get_version(self);
      break;
   case OPEN_STATE_EXIT_BOOTLOADER_MODE:
      if (sensor_is_in_bootloader_mode(self)) {
         send_bootloader_mode_enter_exit(self, FALSE);
      }
      fpi_ssm_next_state(ssm);
      break;
   case OPEN_STATE_LOAD_PAIRING_DATA:
      fetch_pairing_data(self);
      fpi_ssm_next_state(ssm);
      break;
   case OPEN_STATE_VERIFY_SENSOR_CERTIFICATE:;
      verify_sensor_certificate(self, &error);
      if (error != NULL) {
         fpi_ssm_mark_failed(ssm, error);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   case OPEN_STATE_TLS_HS_PREPARE:
      g_assert(!self->tls.established);
      fp_dbg("TLS handshake state: prepare");
      tls_handshake_state_prepare(self);
      fpi_ssm_next_state(ssm);
      break;
   case OPEN_STATE_TLS_HS_STATE_SEND_CLIENT_HELLO:
      tls_handshake_state_start(self);
      break;
   case OPEN_STATE_TLS_HS_STATE_END:
      tls_handshake_state_end(self);
      break;
   case OPEN_STATE_TLS_HS_STATE_FINISHED:
      fp_dbg("TLS handshake state: finished");
      tls_handshake_cleanup(self);
      self->tls.established = TRUE;
      fpi_ssm_mark_completed(ssm);
      break;
   case OPEN_STATE_TLS_HS_STATE_ALERT:
      fp_err("TLS handshake state: alert");
      fp_dbg("\t level = %d; description = %d = %s", self->tls.alert_level,
             self->tls.alert_desc,
             gnutls_alert_get_strname(self->tls.alert_desc));
      send_tls_alert(self, self->tls.alert_level, self->tls.alert_desc);
      break;
   case OPEN_STATE_TLS_HS_STATE_FAILED:
      fp_err("TLS handshake state: failed");
      tls_handshake_cleanup(self);
      /* reset state for later calling of this function */
      self->tls.established = FALSE;

      /* propagate error if present */
      error =
          set_and_report_error(FP_DEVICE_ERROR_PROTO, "TLS handshake failed");
      fpi_ssm_mark_failed(ssm, error);
      break;
   }
}

static void open_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   open_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   if (error != NULL && ssm_data->usb_device_claimed) {
      g_usb_device_release_interface(fpi_device_get_usb_device(device), 0, 0,
                                     NULL);
   }

   self->task_ssm = NULL;
   fp_dbg("<<<<<<<<<<<<<<<<<<<< open end <<<<<<<<<<<<<<<<<<<<");
   fpi_device_open_complete(device, error);
}

static void open(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   open_ssm_data_t *ssm_data = g_new0(open_ssm_data_t, 1);
   GError *error = NULL;

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> open start >>>>>>>>>>>>>>>>>>>>");
   g_assert(self->task_ssm == NULL);

#ifdef TLS_DEBUG
   /* debug check */
   g_assert(sizeof(cert_t) == 400);
#endif

   self->interrupt_cancellable = g_cancellable_new();

   /* Claim usb interface */
   if (!g_usb_device_claim_interface(fpi_device_get_usb_device(device), 0, 0,
                                     &error)) {
      goto error;
   }
   ssm_data->usb_device_claimed = TRUE;

   g_usb_device_reset(fpi_device_get_usb_device(device), &error);

   self->task_ssm = fpi_ssm_new_full(device, open_sm_run_state, OPEN_NUM_STATES,
                                     OPEN_NUM_STATES, "Open");
   fpi_ssm_set_data(self->task_ssm, ssm_data, (GDestroyNotify)g_free);
   fpi_ssm_start(self->task_ssm, open_ssm_done);
   return;

error:
   fpi_device_open_complete(device, error);
   fp_dbg("<<<<<<<<<<<<<<<<<<<< open end <<<<<<<<<<<<<<<<<<<<");
}

/* close =================================================================== */

typedef enum {
   CLOSE_SEND_TLS_CLOSE,
   CLOSE_NUM_STATES,
} close_state_t;

static void close_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   switch (fpi_ssm_get_cur_state(ssm)) {
   case CLOSE_SEND_TLS_CLOSE:
      if (self->tls.established) {
         tls_close_session(self);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   }
}

static void close_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   g_clear_object(&self->interrupt_cancellable);
   deinit_tls(self);
   free_pairing_data(self);

   g_usb_device_release_interface(fpi_device_get_usb_device(FP_DEVICE(self)), 0,
                                  0, &error);

   self->task_ssm = NULL;

   fp_dbg("<<<<<<<<<<<<<<<<<<<< close end <<<<<<<<<<<<<<<<<<<<");
   fpi_device_close_complete(device, error);
}

static void deinit(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> close start >>>>>>>>>>>>>>>>>>>>");
   g_assert(self->task_ssm == NULL);

   self->task_ssm = fpi_ssm_new_full(
       device, close_sm_run_state, CLOSE_NUM_STATES, CLOSE_NUM_STATES, "Close");
   fpi_ssm_start(self->task_ssm, close_ssm_done);
}

/* enroll ================================================================== */

typedef enum {
   ENROLL_STATE_SEND_ENROLL_START,
   ENROLL_STATE_TEST,
   ENROLL_STATE_SET_EVENT_MASK_FINGER_UP,
   ENROLL_STATE_WAIT_FOR_EVENTS1,
   ENROLL_STATE_READ_EVENTS1,
   ENROLL_STATE_CHECK_READ_EVENTS_FINGER_UP,
   // capture image start
   ENROLL_STATE_SET_EVENT_MASK_FRAME_READY,
   ENROLL_STATE_SEND_FRAME_ACQ,
   ENROLL_STATE_SET_EVENT_MASK_STORED,
   ENROLL_STATE_WAIT_FOR_EVENTS2,
   ENROLL_STATE_READ_EVENTS2,
   ENROLL_STATE_CHECK_READ_EVENTS_FRAME_READY_AND_FINGER_DOWN,
   ENROLL_STATE_CLEAR_EVENT_MASK,
   ENROLL_STATE_SEND_FRAME_FINISH,
   // capture image stop
   ENROLL_STATE_SEND_ENROLL_ADD_IMAGE,
   ENROLL_STATE_PROCESS_ENROLL_STATS,
   ENROLL_STATE_SEND_ENROLL_COMMIT,
   ENROLL_STATE_SEND_ENROLL_FINISH,
   ENROLL_NUM_STATES,
} enroll_state_t;

static gboolean check_enroll_status(FpiSsm *ssm, enroll_stats_t *enroll_stats)
{
   enroll_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   if (enroll_stats->status != 0) {
      fp_err("Enroll status %d != 0", enroll_stats->status);
      ssm_data->error = set_and_report_error(
          FP_DEVICE_ERROR_PROTO, "received non-zero enrollment status: %d",
          enroll_stats->status);
      fpi_ssm_jump_to_state(ssm, ENROLL_STATE_SEND_ENROLL_FINISH);
      return FALSE;
   }
   return TRUE;
}

static void notify_enroll_image_rejection(FpiDeviceSynaTudorMoc *self,
                                          enroll_stats_t *enroll_stats)
{
   if (enroll_stats->rejected != 0) {
      GError *retry_error = NULL;
      if (enroll_stats->redundant != 0) {
         fp_info("Image rejected due to being redundant: %u",
                 enroll_stats->redundant);
         retry_error = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                                "Scan is redundant");
      } else {
         fp_info("Image rejected due to bad quality: %u%%",
                 enroll_stats->quality);
         retry_error = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                                "Scan has bad quality");
      }
      fpi_device_enroll_progress(FP_DEVICE(self), enroll_stats->template_cnt,
                                 NULL, retry_error);
   } else {
      fp_info("Image accepted with quality: %u%%", enroll_stats->quality);
      fpi_device_enroll_progress(FP_DEVICE(self), enroll_stats->template_cnt,
                                 NULL, NULL);
   }
}

static void process_enroll_stats(FpiDeviceSynaTudorMoc *self, FpiSsm *ssm)
{
   enroll_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);
   enroll_stats_t *enroll_stats = &self->parsed_recv_data.enroll_stats;

   if (!check_enroll_status(ssm, enroll_stats)) {
      return;
   }
   notify_enroll_image_rejection(self, enroll_stats);

   if (enroll_stats->progress < 100) {
      fpi_ssm_jump_to_state(ssm, ENROLL_STATE_SET_EVENT_MASK_FINGER_UP);
   } else {
      fp_info("Enrollment finished with quality %u",
              enroll_stats->enroll_quality);
      memcpy(ssm_data->match_enrollment.template_id, enroll_stats->template_id,
             DB2_ID_SIZE);
      fp_dbg("Template ID is:");
      fp_dbg_large_hex(ssm_data->match_enrollment.template_id, DB2_ID_SIZE);
      fpi_ssm_next_state(ssm);
   }
}

static void enroll_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   enroll_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   switch (fpi_ssm_get_cur_state(ssm)) {
   case ENROLL_STATE_SEND_ENROLL_START:
      send_enroll_start(self);
      break;
   case ENROLL_STATE_TEST:
      fpi_ssm_jump_to_state(ssm, ENROLL_STATE_SET_EVENT_MASK_FRAME_READY);
      break;
   case ENROLL_STATE_SET_EVENT_MASK_FINGER_UP:
      send_event_config(self, EV_FINGER_UP);
      // FIXME: how to tell the user to lift finger?
      break;
   case ENROLL_STATE_WAIT_FOR_EVENTS1:
      send_interrupt_wait_for_events(self);
      break;
   case ENROLL_STATE_READ_EVENTS1:
      send_event_read(self);
      break;
   case ENROLL_STATE_CHECK_READ_EVENTS_FINGER_UP:
      if ((self->parsed_recv_data.read_event_mask & EV_FINGER_UP) != 0) {
         // FIXME: how to tell the user to finger is up?
         fpi_device_report_finger_status(FP_DEVICE(self),
                                         FP_FINGER_STATUS_NONE);
      }
      if ((self->parsed_recv_data.read_event_mask & EV_FINGER_UP) !=
          EV_FINGER_UP) {
         fpi_ssm_jump_to_state(ssm, ENROLL_STATE_WAIT_FOR_EVENTS1);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   case ENROLL_STATE_SET_EVENT_MASK_FRAME_READY:
      send_event_config(self, EV_FRAME_READY);
      break;
   case ENROLL_STATE_SEND_FRAME_ACQ:
      send_frame_acq(self, CAPTURE_FLAGS_ENROLL);
      ssm_data->event_mask_to_read = EV_FRAME_READY | EV_FINGER_DOWN;
      break;
   case ENROLL_STATE_SET_EVENT_MASK_STORED:
      send_event_config(self, ssm_data->event_mask_to_read);
      fpi_device_report_finger_status(FP_DEVICE(self), FP_FINGER_STATUS_NEEDED);
      break;
   case ENROLL_STATE_WAIT_FOR_EVENTS2:
      send_interrupt_wait_for_events(self);
      break;
   case ENROLL_STATE_READ_EVENTS2:
      send_event_read(self);
      break;
   case ENROLL_STATE_CHECK_READ_EVENTS_FRAME_READY_AND_FINGER_DOWN:
      if ((self->parsed_recv_data.read_event_mask & EV_FINGER_DOWN) != 0) {
         fpi_device_report_finger_status(FP_DEVICE(self),
                                         FP_FINGER_STATUS_PRESENT);
      }
      if ((self->parsed_recv_data.read_event_mask &
           ssm_data->event_mask_to_read) != ssm_data->event_mask_to_read) {
         guint32 new_event_mask_to_read = 0;
         if ((self->parsed_recv_data.read_event_mask & EV_FRAME_READY) == 0) {
            new_event_mask_to_read |= EV_FRAME_READY;
         }
         if ((self->parsed_recv_data.read_event_mask & EV_FINGER_DOWN) == 0) {
            new_event_mask_to_read |= EV_FINGER_DOWN;
         }
         fp_dbg("Did not receive all required events - required event mask: "
                "0b%b, received event mask: 0b%b",
                ssm_data->event_mask_to_read,
                self->parsed_recv_data.read_event_mask);
         fp_dbg("\t-> new event mask: 0b%b", new_event_mask_to_read);
         ssm_data->event_mask_to_read = new_event_mask_to_read;
         fpi_ssm_jump_to_state(ssm, ENROLL_STATE_SET_EVENT_MASK_STORED);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   case ENROLL_STATE_CLEAR_EVENT_MASK:
      send_event_config(self, NO_EVENTS);
      break;
   case ENROLL_STATE_SEND_FRAME_FINISH:
      send_frame_finish(self);
      break;
   case ENROLL_STATE_SEND_ENROLL_ADD_IMAGE:
      send_enroll_add_image(self);
      break;
   case ENROLL_STATE_PROCESS_ENROLL_STATS:
      process_enroll_stats(self, ssm);
      break;
   case ENROLL_STATE_SEND_ENROLL_COMMIT:;
      guint8 *serialized = NULL;
      gsize serialized_size = 0;
      fp_dbg_large_hex(ssm_data->match_enrollment.user_id, WINBIO_SID_SIZE);
      serialize_enrollment_data(self, &ssm_data->match_enrollment, &serialized,
                                &serialized_size, &ssm_data->error);
      if (ssm_data->error != NULL) {
         fpi_ssm_jump_to_state(ssm, ENROLL_STATE_SEND_ENROLL_FINISH);
         return;
      }
      send_enroll_commit(self, serialized, serialized_size);
      g_free(serialized);
      break;
   case ENROLL_STATE_SEND_ENROLL_FINISH:
      // NOTE: this state also functions as a stop to a enrollment if error
      // occures
      send_enroll_finish(self);
      if (ssm_data->error != NULL) {
         fpi_ssm_mark_failed(ssm, ssm_data->error);
      }
      break;
   }
}

static void enroll_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   enroll_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);
   FpPrint *print = NULL;

   if (error != NULL) {
      goto error;
   }

   print = fp_print_from_enrollment(self, &ssm_data->match_enrollment);
   fpi_device_enroll_complete(device, g_object_ref(print), NULL);

error:
   fp_dbg("<<<<<<<<<<<<<<<<<<<< enroll end <<<<<<<<<<<<<<<<<<<<");
   self->task_ssm = NULL;
   fpi_device_enroll_complete(device, print, error);
}

static void enroll(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   FpPrint *enroll_data_print = NULL;
   enroll_ssm_data_t *ssm_data;
   g_autofree char *user_id_str = NULL;

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> enroll start >>>>>>>>>>>>>>>>>>>>");

   g_assert(self->task_ssm == NULL);

   self->task_ssm =
       fpi_ssm_new_full(device, enroll_sm_run_state, ENROLL_NUM_STATES,
                        ENROLL_NUM_STATES, "Enroll");

   ssm_data = g_new0(enroll_ssm_data_t, 1);

   fpi_device_get_enroll_data(device, &enroll_data_print);
   user_id_str = fpi_print_generate_user_id(enroll_data_print);
   gsize user_id_str_len = strlen(user_id_str);
   memcpy(ssm_data->match_enrollment.user_id, user_id_str, user_id_str_len);
   ssm_data->match_enrollment.finger_id =
       fp_print_get_finger(enroll_data_print);

   fp_dbg("Trying to enroll print with:");
   fp_dbg("\tuser_id:");
   fp_dbg_large_hex(ssm_data->match_enrollment.user_id, sizeof(user_id_t));
   fp_dbg("\tfinger_id: %u", ssm_data->match_enrollment.finger_id);

   fpi_ssm_set_data(self->task_ssm, ssm_data, (GDestroyNotify)g_free);

   fpi_ssm_start(self->task_ssm, enroll_ssm_done);
}

/* auth ==================================================================== */

typedef enum {
   // capture image start
   AUTH_STATE_SET_EVENT_MASK_FRAME_READY,
   AUTH_STATE_SEND_FRAME_ACQ,
   AUTH_STATE_SET_EVENT_MASK_STORED,
   AUTH_STATE_WAIT_FOR_EVENTS,
   AUTH_STATE_READ_EVENTS,
   AUTH_STATE_CHECK_READ_EVENTS,
   AUTH_STATE_CLEAR_EVENT_MASK,
   AUTH_STATE_SEND_FRAME_FINISH,
   // capture image stop
   AUTH_STATE_GET_IMAGE_METRICS,
   AUTH_STATE_CHECK_IMAGE_QUALITY,
   AUTH_STATE_IDENTIFY_IMAGE,
   AUTH_NUM_STATES,
} auth_state_t;

static void check_image_quality(FpiSsm *ssm, guint32 img_quality)
{
   if (img_quality < IMAGE_QUALITY_THRESHOLD) {
      fp_info("Image quality %d%% is lower than threshold %d%%", img_quality,
              IMAGE_QUALITY_THRESHOLD);
      fpi_ssm_mark_failed(ssm,
                          set_and_report_error(
                              FP_DEVICE_ERROR_GENERAL,
                              "Image quality %d%% is lower than threshold %d%%",
                              img_quality, IMAGE_QUALITY_THRESHOLD));
   } else {
      fpi_ssm_next_state(ssm);
   }
}

static void auth_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   auth_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   switch (fpi_ssm_get_cur_state(ssm)) {
   case AUTH_STATE_SET_EVENT_MASK_FRAME_READY:
      send_event_config(self, EV_FRAME_READY);
      break;
   case AUTH_STATE_SEND_FRAME_ACQ:
      send_frame_acq(self, CAPTURE_FLAGS_AUTH);
      ssm_data->event_mask_to_read = EV_FRAME_READY | EV_FINGER_DOWN;
      break;
   case AUTH_STATE_SET_EVENT_MASK_STORED:
      send_event_config(self, ssm_data->event_mask_to_read);
      fpi_device_report_finger_status(FP_DEVICE(self), FP_FINGER_STATUS_NEEDED);
      break;
   case AUTH_STATE_WAIT_FOR_EVENTS:
      send_interrupt_wait_for_events(self);
      break;
   case AUTH_STATE_READ_EVENTS:
      send_event_read(self);
      break;
   case AUTH_STATE_CHECK_READ_EVENTS:
      if ((self->parsed_recv_data.read_event_mask & EV_FINGER_DOWN) != 0) {
         fpi_device_report_finger_status(FP_DEVICE(self),
                                         FP_FINGER_STATUS_PRESENT);
      }
      if ((self->parsed_recv_data.read_event_mask &
           ssm_data->event_mask_to_read) != ssm_data->event_mask_to_read) {
         guint32 new_event_mask_to_read = 0;
         if ((self->parsed_recv_data.read_event_mask & EV_FRAME_READY) == 0) {
            new_event_mask_to_read |= EV_FRAME_READY;
         }
         if ((self->parsed_recv_data.read_event_mask & EV_FINGER_DOWN) == 0) {
            new_event_mask_to_read |= EV_FINGER_DOWN;
         }
         fp_dbg("Did not receive all required events - required event mask: "
                "0b%b, received event mask: 0b%b",
                ssm_data->event_mask_to_read,
                self->parsed_recv_data.read_event_mask);
         fp_dbg("\t-> new event mask: 0b%b", new_event_mask_to_read);
         ssm_data->event_mask_to_read = new_event_mask_to_read;
         fpi_ssm_jump_to_state(ssm, AUTH_STATE_SET_EVENT_MASK_STORED);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   case AUTH_STATE_CLEAR_EVENT_MASK:
      send_event_config(self, NO_EVENTS);
      break;
   case AUTH_STATE_SEND_FRAME_FINISH:
      send_frame_finish(self);
      break;
   case AUTH_STATE_GET_IMAGE_METRICS:
      send_get_image_metrics(self, MIS_IMAGE_METRICS_IMG_QUALITY);
      break;
   case AUTH_STATE_CHECK_IMAGE_QUALITY:;
      guint32 img_quality =
          self->parsed_recv_data.img_metrics.data.matcher_stats.img_quality;
      check_image_quality(ssm, img_quality);
      break;
   case AUTH_STATE_IDENTIFY_IMAGE:
      if (ssm_data->verify_template_id_present) {
         send_identify_match(self, &ssm_data->verify_template_id, 1);
      } else {
         send_identify_match(self, NULL, 0);
      }
      break;
   }
}

static void auth_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   if (error != NULL) {
      goto error;
   }

   match_result_t *match_result = &self->parsed_recv_data.match_result;
   fp_dbg("Identify matched: %s", match_result->matched ? "TRUE" : "FALSE");

   if (self->parsed_recv_data.match_result.matched) {
      FpPrint *matching = NULL;
      FpPrint *new_scan =
          fp_print_from_enrollment(self, &match_result->matched_enrollment);

      fp_dbg("Auth match got enrollment:");
      fp_dbg_enrollment(&match_result->matched_enrollment);

      if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY) {
         fpi_device_verify_report(device, FPI_MATCH_SUCCESS, new_scan, error);
      } else {
         GPtrArray *templates = NULL;
         fpi_device_get_identify_data(device, &templates);
         for (gint i = 0; i < templates->len; ++i) {
            if (fp_print_equal(g_ptr_array_index(templates, i), new_scan)) {
               matching = g_ptr_array_index(templates, i);
               break;
            }
         }
         fpi_device_identify_report(device, matching, new_scan, NULL);
      }
   } else {
      /* we get no print data on no match */
      if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY) {
         fpi_device_verify_report(device, FPI_MATCH_FAIL, NULL, NULL);
      } else {
         fpi_device_identify_report(device, NULL, NULL, NULL);
      }
   }

error:
   self->task_ssm = NULL;
   if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY) {
      fp_dbg("<<<<<<<<<<<<<<<<<<<< auth - verify end <<<<<<<<<<<<<<<<<<<<");
      fpi_device_verify_complete(device, error);
   } else {
      fp_dbg("<<<<<<<<<<<<<<<<<<<< auth - identify end <<<<<<<<<<<<<<<<<<<<");
      fpi_device_identify_complete(device, error);
   }
}

static void auth(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   G_DEBUG_HERE();
   if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY) {
      fp_dbg(">>>>>>>>>>>>>>>>>>>> auth - verify start >>>>>>>>>>>>>>>>>>>>");
   } else {
      fp_dbg(">>>>>>>>>>>>>>>>>>>> auth - identify start >>>>>>>>>>>>>>>>>>>>");
   }

   g_assert(self->task_ssm == NULL);
   FpPrint *print_to_verify = NULL;
   g_autoptr(GVariant) fp_data = NULL;
   GError *error = NULL;

   self->task_ssm = fpi_ssm_new_full(device, auth_sm_run_state, AUTH_NUM_STATES,
                                     AUTH_NUM_STATES, "Auth");

   auth_ssm_data_t *ssm_data = g_new0(auth_ssm_data_t, 1);
   if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY) {
      fpi_device_get_verify_data(device, &print_to_verify);
      g_object_get(print_to_verify, "fpi-data", &fp_data, NULL);
      if (!get_template_id_from_print_data(
              fp_data, ssm_data->verify_template_id, &error)) {
         goto error;
      }
      ssm_data->verify_template_id_present = TRUE;
      fp_dbg("Verifying print with template id:");
      fp_dbg_large_hex(ssm_data->verify_template_id, DB2_ID_SIZE);
   }
   fpi_ssm_set_data(self->task_ssm, ssm_data, (GDestroyNotify)g_free);

   fpi_ssm_start(self->task_ssm, auth_ssm_done);
   return;

error:
   if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY) {
      fp_dbg("<<<<<<<<<<<<<<<<<<<< auth - verify end <<<<<<<<<<<<<<<<<<<<");
   } else {
      fp_dbg("<<<<<<<<<<<<<<<<<<<< auth - identify end <<<<<<<<<<<<<<<<<<<<");
   }
   self->task_ssm = NULL;
   fpi_device_identify_complete(device, error);
}

/* list ==================================================================== */

typedef enum {
   LIST_STATE_GET_CURRENT_NUMBER_OF_DB2_OBJECTS,
   LIST_STATE_CLEANUP,
   LIST_STATE_GET_TEMPLATE_LIST,
   LIST_STATE_STORE_TEMPLATE_LIST,
   LIST_STATE_GET_PAYLOAD_LIST,
   LIST_STATE_STORE_PAYLOAD_LIST,
   LIST_STATE_GET_PAYLOAD_SIZE,
   LIST_STATE_GET_PAYLOAD_DATA,
   LIST_STATE_STORE_PAYLOAD_DATA,
   LIST_NUM_STATES,
} list_state_t;

static void list_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   list_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   switch (fpi_ssm_get_cur_state(ssm)) {
   case LIST_STATE_GET_CURRENT_NUMBER_OF_DB2_OBJECTS:
      send_db2_info(self);
      break;
   case LIST_STATE_CLEANUP:
      if (self->parsed_recv_data.cleanup_required) {
         send_db2_cleanup(self);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   case LIST_STATE_GET_TEMPLATE_LIST:
      send_db2_get_object_list(self, OBJ_TYPE_TEMPLATES, cache_template_id);
      break;
   case LIST_STATE_STORE_TEMPLATE_LIST:
      ssm_data->template_id_cnt = self->parsed_recv_data.db2_obj_list.len;
      if (ssm_data->template_id_cnt == 0) {
         fp_dbg("database is empty");
         fpi_ssm_mark_completed(ssm);
         return;
      }
      ssm_data->template_id_list = self->parsed_recv_data.db2_obj_list.obj_list;
      fpi_ssm_next_state(ssm);
      break;
   case LIST_STATE_GET_PAYLOAD_LIST:
      send_db2_get_object_list(
          self, OBJ_TYPE_PAYLOADS,
          ssm_data->template_id_list[ssm_data->current_template_id_idx++]);
      break;
   case LIST_STATE_STORE_PAYLOAD_LIST:
      g_array_append_vals(ssm_data->payload_id_list,
                          self->parsed_recv_data.db2_obj_list.obj_list,
                          self->parsed_recv_data.db2_obj_list.len);
      g_free(self->parsed_recv_data.db2_obj_list.obj_list);

      if (ssm_data->current_template_id_idx < ssm_data->template_id_cnt) {
         fpi_ssm_jump_to_state(ssm, LIST_STATE_GET_PAYLOAD_LIST);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   case LIST_STATE_GET_PAYLOAD_SIZE:
      if (ssm_data->payload_id_list->len == 0) {
         fp_dbg("database is empty");
         fpi_ssm_mark_completed(ssm);
         return;
      }

      fp_dbg("Getting payload at idx: %d/%d", ssm_data->current_payload_id_idx,
             ssm_data->payload_id_list->len - 1);
      fp_dbg_large_hex(g_array_index(ssm_data->payload_id_list, db2_id_t,
                                     ssm_data->current_payload_id_idx),
                       DB2_ID_SIZE);

      send_db2_get_object_info(self, OBJ_TYPE_PAYLOADS,
                               g_array_index(ssm_data->payload_id_list,
                                             db2_id_t,
                                             ssm_data->current_payload_id_idx));
      break;
   case LIST_STATE_GET_PAYLOAD_DATA:;
      const guint size_offset = 48;
      const guint min_expected_size = size_offset + sizeof(guint32);
      if (self->parsed_recv_data.raw_resp.size < min_expected_size) {
         fpi_ssm_mark_failed(
             ssm, set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                       "Received raw data is too short to get "
                                       "payload size - got: %lu, expected: >%u",
                                       self->parsed_recv_data.raw_resp.size,
                                       min_expected_size));
      }
      guint obj_data_size = FP_READ_UINT32_LE(
          &((self->parsed_recv_data.raw_resp.data)[size_offset]));
      g_free(self->parsed_recv_data.raw_resp.data);

      send_db2_get_object_data(self, OBJ_TYPE_PAYLOADS,
                               g_array_index(ssm_data->payload_id_list,
                                             db2_id_t,
                                             ssm_data->current_payload_id_idx),
                               obj_data_size);
      ssm_data->current_payload_id_idx += 1;
      break;
   case LIST_STATE_STORE_PAYLOAD_DATA:;
      GError *error = NULL;
      enrollment_t enrollment = {0};
      get_enrollment_data_from_serialized_container(
          self->parsed_recv_data.db2_obj_data.data,
          self->parsed_recv_data.db2_obj_data.size, &enrollment, &error);
      g_free(self->parsed_recv_data.db2_obj_data.data);
      if (error != NULL) {
         fpi_ssm_mark_failed(ssm, error);
      }
      FpPrint *print = fp_print_from_enrollment(self, &enrollment);
      g_ptr_array_add(ssm_data->fp_print_array, g_object_ref_sink(print));

      if (ssm_data->current_payload_id_idx < ssm_data->payload_id_list->len) {
         fpi_ssm_jump_to_state(ssm, LIST_STATE_GET_PAYLOAD_SIZE);
      } else {
         fpi_ssm_next_state(ssm);
      }
      break;
   }
}

static void list_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   list_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   if (error != NULL) {
      goto error;
   }

   if (ssm_data->fp_print_array->len == 0) {
      fp_warn("Database is empty");
   }

error:
   fp_dbg("<<<<<<<<<<<<<<<<<<<< list end <<<<<<<<<<<<<<<<<<<<");
   self->task_ssm = NULL;
   if (error != NULL) {
      g_ptr_array_free(ssm_data->fp_print_array, TRUE);
      fpi_device_list_complete(device, NULL, error);
   } else {
      fpi_device_list_complete(device, ssm_data->fp_print_array, error);
   }
}

static void free_list_ssm_data_t(list_ssm_data_t *ssm_data)
{
   g_array_free(ssm_data->payload_id_list, TRUE);
   g_free(ssm_data->template_id_list);
   g_free(ssm_data);
}

static void list(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> list start >>>>>>>>>>>>>>>>>>>>");
   g_assert(self->task_ssm == NULL);

   self->task_ssm = fpi_ssm_new_full(device, list_sm_run_state, LIST_NUM_STATES,
                                     LIST_NUM_STATES, "List");

   list_ssm_data_t *ssm_data = g_new0(list_ssm_data_t, 1);
   ssm_data->fp_print_array = g_ptr_array_new_with_free_func(g_object_unref);
   ssm_data->payload_id_list = g_array_new(FALSE, FALSE, DB2_ID_SIZE);
   fpi_ssm_set_data(self->task_ssm, ssm_data,
                    (GDestroyNotify)free_list_ssm_data_t);

   fpi_ssm_start(self->task_ssm, list_ssm_done);
}

/* delete ================================================================== */

typedef enum {
   DELETE_SEND_DB2_DELETE,
   DELETE_NUM_STATES,
} delete_state_t;

static void delete_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   delete_ssm_data_t *ssm_data = fpi_ssm_get_data(ssm);

   switch (fpi_ssm_get_cur_state(ssm)) {
   case DELETE_SEND_DB2_DELETE:
      send_db2_delete_object(self, OBJ_TYPE_TEMPLATES, ssm_data->template_id);
      break;
   }
}

static void delete_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   fp_dbg("<<<<<<<<<<<<<<<<<<<< delete end <<<<<<<<<<<<<<<<<<<<");
   self->task_ssm = NULL;
   fpi_device_delete_complete(device, error);
}

static void delete(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   GError *error = NULL;
   delete_ssm_data_t *ssm_data = g_new0(delete_ssm_data_t, 1);

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> delete start >>>>>>>>>>>>>>>>>>>>");
   g_assert(self->task_ssm == NULL);

   FpPrint *print_to_delete = NULL;
   fpi_device_get_delete_data(device, &print_to_delete);

   g_autoptr(GVariant) delete_fpi_data = NULL;
   g_object_get(print_to_delete, "fpi-data", &delete_fpi_data, NULL);

   if (!get_template_id_from_print_data(delete_fpi_data, ssm_data->template_id,
                                        &error)) {
      fp_dbg("<<<<<<<<<<<<<<<<<<<< delete end <<<<<<<<<<<<<<<<<<<<");
      fpi_device_delete_complete(device, error);
      return;
   }

   fp_dbg("Deleting print with template ID:");
   fp_dbg_large_hex(ssm_data->template_id, DB2_ID_SIZE);

   self->task_ssm =
       fpi_ssm_new_full(device, delete_sm_run_state, DELETE_NUM_STATES,
                        DELETE_NUM_STATES, "Delete");
   fpi_ssm_set_data(self->task_ssm, ssm_data, (GDestroyNotify)g_free);
   fpi_ssm_start(self->task_ssm, delete_ssm_done);
}

/* clear_storage =========================================================== */

typedef enum {
   CLEAR_STORAGE_SEND_DB2_FORMAT,
   CLEAR_STORAGE_NUM_STATES,
} clear_storage_state_t;

static void clear_storage_sm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);
   switch (fpi_ssm_get_cur_state(ssm)) {
   case CLEAR_STORAGE_SEND_DB2_FORMAT:
      send_db2_format(self);
      break;
   }
}

static void clear_storage_ssm_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   fp_dbg("<<<<<<<<<<<<<<<<<<<< clear storage end <<<<<<<<<<<<<<<<<<<<");
   self->task_ssm = NULL;
   fpi_device_clear_storage_complete(device, error);
}

static void clear_storage(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> clear storage start >>>>>>>>>>>>>>>>>>>>");
   g_assert(self->task_ssm == NULL);

   self->task_ssm = fpi_ssm_new_full(device, clear_storage_sm_run_state,
                                     CLEAR_STORAGE_NUM_STATES,
                                     CLEAR_STORAGE_NUM_STATES, "Clear storage");
   fpi_ssm_start(self->task_ssm, clear_storage_ssm_done);
}

/* cancel ================================================================== */

static void cancel(FpDevice *device)
{
   FpiDeviceSynaTudorMoc *self = FPI_DEVICE_SYNA_TUDOR_MOC(device);

   G_DEBUG_HERE();
   fp_dbg(">>>>>>>>>>>>>>>>>>>> cancel start >>>>>>>>>>>>>>>>>>>>");

   /* cancel ongoing interrupt transfers */
   g_cancellable_cancel(self->interrupt_cancellable);

   fp_dbg("<<<<<<<<<<<<<<<<<<<< cancel end <<<<<<<<<<<<<<<<<<<<");
}

/* class init ============================================================== */

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

   dev_class->open = open;
   dev_class->close = deinit; // close name is taken by another funciton name
   dev_class->enroll = enroll;
   dev_class->verify = auth;
   dev_class->identify = auth;
   dev_class->list = list;
   dev_class->delete = delete;
   dev_class->clear_storage = clear_storage;
   dev_class->cancel = cancel;

   fpi_device_class_auto_initialize_features(dev_class);
}
