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

#define FP_COMPONENT "synatlsmoc"

#include <glib.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>

#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "fpi-device.h"
#include "fpi-log.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"
#include "sample_pairing_data.h"
#include "sensor_public_keys.h"
#include "synatlsmoc.h"
#include "tagval.h"
#include "tls_session.h"
#include "utils.h"

/* Some important notes for this driver */
/* WARN: this driver may not work (cannot test it), if the sensor is not once
 * initialized in Windows */
/* WARN: current implementation starts a new TLS session on each device open */

// #define DEBUG

/* Needed for testing with libfprint examples they do not support storage of
 * pairing data */
// #define USE_SAMPLE_PAIRING_DATA

guint8 cache_tuid[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// FIXME: why FpDevice in callback and not FpiDeviceSynaTlsMoc
typedef void (*CmdCallback)(FpDevice *device, guchar *buffer_in,
                            gsize length_in, GError *error);

typedef struct CmdData
{
  gboolean raw;
  gboolean check_res;
  gsize length_in;
  CmdCallback callback;
} CmdData;

struct _FpiDeviceSynaTlsMoc
{
  FpDevice parent;
  FpiSsm *task_ssm;
  FpiSsm *cmd_ssm;
  FpiUsbTransfer *cmd_transfer;
  GCancellable *interrupt_cancellable;

  guint8 fw_version_major;
  guint8 fw_version_minor;
  guint8 product;
  guint8 security;
  guint64 iface;
  guint8 provision_state;

  SensorPairingData pairing_data;
  /* NOTE: host/this driver is the client, sensor is server */
  TlsSession *session;
  gboolean server_established;

  guint16 event_seq_num;
  guint32 event_mask;
  guint32 event_recv;
  guint num_pending_events;
  gboolean event_read_in_legacy_mode;
};

G_DEFINE_TYPE(FpiDeviceSynaTlsMoc, fpi_device_synatlsmoc, FP_TYPE_DEVICE);

// clang-format off
static const FpIdEntry id_table[] = {
    /* the sensors commented out are untested, but should be suported */
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00C9, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00D1, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x00E7, },
    { .vid = SYNAPTICS_VENDOR_ID, .pid = 0x00FF, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0124, },
    // { .vid = SYNAPTICS_VENDOR_ID,  .pid = 0x0169, },
    { .vid = SYNAPTICS_VENDOR_ID, .pid = 0x016C, },
    { .vid = 0, .pid = 0, .driver_data = 0 }, /* terminating entry */
};
// clang-format on

static gboolean synatlsmoc_is_in_bootloader_mode(FpiDeviceSynaTlsMoc *self)
{
  guint8 product = self->product;

  return product == BOOTLOADER_A || product == BOOTLOADER_B ||
         product == BOOTLOADER_C || product == BOOTLOADER_D;
}

static gboolean synatlsmoc_is_provisioned(FpiDeviceSynaTlsMoc *self)
{
  return (self->provision_state & PROVISION_STATE_MASK) == PROVISIONED;
}

static gboolean synatlsmoc_has_advanced_security(FpiDeviceSynaTlsMoc *self)
{
  return (self->security & ADVANCED_SECURITY_MASK) != 0;
}

static gboolean synatlsmoc_key_flag(FpiDeviceSynaTlsMoc *self)
{
  return (self->iface & KEY_FLAG_MASK) != 0;
}

static gboolean load_uncompressed_public_key(guint8 *key, gsize key_len,
                                             EVP_PKEY **pkey, GError **error)
{
  g_autoptr(OSSL_PARAM_BLD) param_bld = OSSL_PARAM_BLD_new();

  if (param_bld == NULL ||
      !OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", key, key_len))
  {
    g_propagate_error(
        error, set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "Failed to parse public key: %s",
                                    ERR_error_string(ERR_get_error(), NULL)));
    return FALSE;
  }

  g_autoptr(OSSL_PARAM) params = OSSL_PARAM_BLD_to_param(param_bld);
  g_autoptr(EVP_PKEY_CTX) ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

  if (ctx == NULL || params == NULL || !EVP_PKEY_fromdata_init(ctx) ||
      !EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params))
  {
    g_propagate_error(
        error, set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                    "Failed to load public key: %s",
                                    ERR_error_string(ERR_get_error(), NULL)));
    return FALSE;
  }

  return TRUE;
}

static gboolean sensor_pub_key_compatibility_check(
    FpiDeviceSynaTlsMoc *self, sensor_pub_key_t *sensor_pubkey, GError **error)
{
  gboolean ret = TRUE;

  if (sensor_pubkey->keyflag != synatlsmoc_key_flag(self))
  {
    ret = FALSE;
    *error = set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "Sensor pubkey keyflag does not match");
  }
  else if (sensor_pubkey->fw_version_major != self->fw_version_major)
  {
    ret = FALSE;
    *error = set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "Sensor pubkey fw_version_major does "
                                  "not match - expected: %d, got: %d",
                                  sensor_pubkey->fw_version_major,
                                  self->fw_version_major);
  }
  else if (sensor_pubkey->fw_version_minor != self->fw_version_minor)
  {
    ret = FALSE;
    *error = set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "Sensor pubkey fw_version_minor does "
                                  "not match - expected: %d, got: %d",
                                  sensor_pubkey->fw_version_minor,
                                  self->fw_version_minor);
  }
  return ret;
}

static void synatlsmoc_load_sensor_key(FpiDeviceSynaTlsMoc *self)
{
  GError *local_error = NULL;
  OpenData *ssm_data = fpi_ssm_get_data(self->task_ssm);

  sensor_pub_key_t *sensor_pub_key;
  if (synatlsmoc_key_flag(self))
    sensor_pub_key = &pubkey_v10_1_kf;
  else
    sensor_pub_key = &pubkey_v10_1;

  if (!sensor_pub_key_compatibility_check(self, sensor_pub_key, &local_error))
  {
    fpi_ssm_mark_failed(self->task_ssm, local_error);
    return;
  }

  if (!load_uncompressed_public_key(sensor_pub_key->key_data,
                                    sensor_pub_key->key_data_size,
                                    &ssm_data->pub_key, &local_error))
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_NOT_SUPPORTED,
                             "Error while loading sensor key: %s",
                             local_error->message));
    g_error_free(local_error);
    return;
  }

  fpi_ssm_next_state(self->task_ssm);
}

static void synatlsmoc_verify_sensor_certificate(FpiDeviceSynaTlsMoc *self)
{
  fp_dbg("Verifying sensor certificate...");
  OpenData *ssm_data = fpi_ssm_get_data(self->task_ssm);

  // FIXME: freeing causes issues?
  // g_autoptr(EVP_MD_CTX) mdctx = EVP_MD_CTX_create();
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL,
                           ssm_data->pub_key) <= 0 ||
      EVP_DigestVerifyUpdate(mdctx, self->pairing_data.server_cert_raw,
                             CERTIFICATE_DATA_SIZE) <= 0 ||
      EVP_DigestVerifyFinal(mdctx, self->pairing_data.server_cert.sign,
                            self->pairing_data.server_cert.sign_size) <= 0)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(
            FP_DEVICE_ERROR_GENERAL,
            "OpenSSL error occured while verifying sensor certificate: %s",
            ERR_error_string(ERR_get_error(), NULL)));
    return;
  }

  EVP_PKEY_free(ssm_data->pub_key);

  fp_dbg("Sensor certificate is valid");

  fpi_ssm_next_state(self->task_ssm);
}

static gboolean sensor_certificate_from_raw(Certificate *self, guint8 *data,
                                            gsize len, GError **error)
{
  GError *local_error = NULL;
  gboolean read_ok = TRUE;
  FpiByteReader reader;

  if (len != CERTIFICATE_SIZE)
  {
    g_propagate_error(
        error,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "Certificate with incorrect length: %lu", len));
    return FALSE;
  }

  fpi_byte_reader_init(&reader, data, len);

  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &self->magic);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &self->curve);
  read_ok &= fpi_byte_reader_dup_data(&reader, ECC_KEY_SIZE, &self->x);
  read_ok &= fpi_byte_reader_skip(&reader, 36);
  read_ok &= fpi_byte_reader_dup_data(&reader, ECC_KEY_SIZE, &self->y);
  read_ok &= fpi_byte_reader_skip(&reader, 36);
  read_ok &= fpi_byte_reader_skip(&reader, 1);
  read_ok &= fpi_byte_reader_get_uint8(&reader, &self->cert_type);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &self->sign_size);
  read_ok &= fpi_byte_reader_dup_data(&reader, 256, &self->sign);

  if (self->magic != CERTIFICATE_MAGIC || self->curve != CERTIFICATE_CURVE)
  {
    g_propagate_error(error,
                      set_and_report_error(
                          FP_DEVICE_ERROR_PROTO,
                          "Unsupported certificate: magic=0x%04x, curve=0x%02x",
                          self->magic, self->curve));
    return FALSE;
  }

  // This should have no way of failing though
  RETURN_FALSE_AND_SET_ERROR_IF_NOT_READ(read_ok);

  /* the keys are stored in little endian - reverse them as OpenSSL expects big
   * endian */
  reverse_array(self->x, ECC_KEY_SIZE);
  reverse_array(self->y, ECC_KEY_SIZE);

  /* uncompressed public key is stored as:
   * POINT_CONVERSION_UNCOMPRESSED + x_coord + y_coord */
  guint8 uncompressed_pubkey[1 + 2 * ECC_KEY_SIZE];
  uncompressed_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;
  memcpy(&uncompressed_pubkey[1], self->x, ECC_KEY_SIZE);
  memcpy(&uncompressed_pubkey[1 + ECC_KEY_SIZE], self->y, ECC_KEY_SIZE);

  if (!load_uncompressed_public_key(uncompressed_pubkey, 1 + 2 * ECC_KEY_SIZE,
                                    &self->pub_key, &local_error))
  {
    g_propagate_error(error, local_error);
    return FALSE;
  }

  g_autofree gchar *x_str = bin2hex(self->x, ECC_KEY_SIZE);
  g_autofree gchar *y_str = bin2hex(self->y, ECC_KEY_SIZE);
  g_autofree gchar *sign_str = bin2hex(self->sign, self->sign_size);
  fp_dbg("Certificate:");
  fp_dbg("\tmagic: 0x%04x", self->magic);
  fp_dbg("\tcurve: 0x%04x", self->curve);
  fp_dbg("\tpub_x: %s", x_str);
  fp_dbg("\tpub_y: %s", y_str);
  fp_dbg("\tcert_type: 0x%02x", self->cert_type);
  fp_dbg("\tsign_size: 0x%04x", self->sign_size);
  fp_dbg("\tsignature: %s", sign_str);

  return TRUE;
}

static gboolean parse_certificates_within_self(FpiDeviceSynaTlsMoc *self,
                                               GError **error)
{
  GError *local_error = NULL;
  if (!sensor_certificate_from_raw(
          &self->pairing_data.client_cert, self->pairing_data.client_cert_raw,
          self->pairing_data.client_cert_len, &local_error))
  {
    g_propagate_error(
        error, set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                    "Cannot parse client certificate: %s",
                                    local_error->message));
    return FALSE;
  }

  if (!sensor_certificate_from_raw(
          &self->pairing_data.server_cert, self->pairing_data.server_cert_raw,
          self->pairing_data.server_cert_len, &local_error))
  {
    g_propagate_error(
        error, set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                    "Cannot parse server certificate: %s",
                                    local_error->message));
    return FALSE;
  }

  return TRUE;
}

static void synatlsmoc_ssm_next_state_cb(FpDevice *device, guchar *buffer_in,
                                         gsize length_in, GError *error)
{
  fp_dbg("Task SSM next state callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
    fpi_ssm_mark_failed(self->task_ssm, error);
  else
    fpi_ssm_next_state(self->task_ssm);
}

static void synatlsmoc_task_ssm_done(FpiSsm *ssm, FpDevice *device,
                                     GError *error)
{
  fp_dbg("Task SSM done");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  /* task_ssm is going to be freed by completion of SSM */
  g_assert(!self->task_ssm || self->task_ssm == ssm);
  self->task_ssm = NULL;

  if (error) fpi_device_action_error(device, error);
}

static gboolean status_is_success(guint16 status)
{
  return status == VCS_RESULT_OK_1 || status == VCS_RESULT_OK_2 ||
         status == VCS_RESULT_OK_3 || status == VCS_RESULT_OK_4;
}

static gboolean sensor_status_is_result_bad_param(guint16 status)
{
  return (status == VCS_RESULT_GEN_BAD_PARAM_1 ||
          status == VCS_RESULT_GEN_BAD_PARAM_2 ||
          status == VCS_RESULT_GEN_BAD_PARAM_3);
}

static void synatlsmoc_cmd_receive_cb(FpiUsbTransfer *transfer,
                                      FpDevice *device, gpointer userdata,
                                      GError *error)
{
  fp_dbg("Command receive callback");

  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  CmdData *data = userdata;
  CmdCallback callback;
  GError *local_error = NULL;
  guint16 status = 0xFFFF; /* 0 would mean success */
  g_autofree guint8 *unwrapped = NULL;
  gsize unwrapped_len = 0;

  if (error)
  {
    fpi_ssm_mark_failed(transfer->ssm, error);
    return;
  }

  if (self->session && !data->raw)
  {
#ifdef DEBUG
    g_autofree char *recv_wrapped_str =
        bin2hex(transfer->buffer, transfer->actual_length);
    fp_dbg("\twresp: %s", recv_wrapped_str);
#endif

    tls_session_unwrap(self->session, transfer->buffer, transfer->actual_length,
                       &unwrapped, &unwrapped_len, &local_error);
    if (local_error)
    {
      fpi_ssm_mark_failed(transfer->ssm, local_error);
      return;
    }
  }
  else
  {
    unwrapped = g_steal_pointer(&transfer->buffer);
    unwrapped_len = transfer->actual_length;
  }

#ifdef DEBUG
  g_autofree char *recv_str = bin2hex(unwrapped, unwrapped_len);
  fp_dbg("\trecv: %s", recv_str);
#endif

  if (!data->raw)
  {
    if (unwrapped_len < SENSOR_FW_REPLY_STATUS_HEADER_LEN)
    {
      fpi_ssm_mark_failed(
          transfer->ssm,
          set_and_report_error(FP_DEVICE_ERROR_PROTO, "Invalid response"));
      return;
    }

    status = FP_READ_UINT16_LE(unwrapped);

    fp_dbg("RESP <- 0x%04x - %s", status, status_to_str(status));

    if (data->check_res && !status_is_success(status))
    {
      fpi_ssm_mark_failed(transfer->ssm,
                          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                               "Command failed with status: %s",
                                               status_to_str(status)));
      return;
    }
  }

  /* Let's complete the previous ssm and then handle the callback, so that
   * we are sure that we won't start a transfer or a new command while there is
   * another one still ongoing
   */
  callback = data->callback;

  fpi_ssm_mark_completed(transfer->ssm);

  if (callback) callback(device, unwrapped, unwrapped_len, NULL);
}

static void synatlsmoc_cmd_run_state(FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  g_autoptr(FpiUsbTransfer) transfer = NULL;
  CmdData *data = fpi_ssm_get_data(ssm);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case CMD_SEND:
      if (self->cmd_transfer)
      {
        self->cmd_transfer->ssm = ssm;
        fpi_usb_transfer_submit(g_steal_pointer(&self->cmd_transfer),
                                SYNATLSMOC_USB_SEND_TIMEOUT, NULL,
                                fpi_ssm_usb_transfer_cb, NULL);
      }
      break;
    case CMD_RECV:
      transfer = fpi_usb_transfer_new(device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk(transfer, SYNATLSMOC_EP_RESP_IN,
                                 data->length_in);
      fpi_usb_transfer_submit(
          g_steal_pointer(&transfer), SYNATLSMOC_USB_RECV_TIMEOUT,
          fpi_device_get_cancellable(device), synatlsmoc_cmd_receive_cb, data);
      break;
  }
}

static void synatlsmoc_cmd_ssm_done(FpiSsm *ssm, FpDevice *device,
                                    GError *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  CmdData *data = fpi_ssm_get_data(ssm);

  g_assert(self->cmd_ssm == ssm);
  g_assert(!self->cmd_transfer || self->cmd_transfer->ssm == ssm);

  self->cmd_ssm = NULL;
  self->cmd_transfer = NULL;

  if (error && data && data->callback)
    data->callback(device, NULL, 0, g_steal_pointer(&local_error));
}

/* NOTE: buffer_in in callback is automatically freed when callback returns
 */
static void synatlsmoc_exec_cmd(FpiDeviceSynaTlsMoc *self, gboolean raw,
                                gboolean check_res, guint8 *cmd, gsize cmd_size,
                                gsize resp_size, CmdCallback callback)
{
  fp_dbg("Execute command and get response");
  FpDevice *device = FP_DEVICE(self);
  CmdData *data = g_new0(CmdData, 1);
  GError *local_error = NULL;
  guint8 *wrapped;
  gsize wrapped_len;
#ifdef DEBUG
  g_autofree char *wrapped_str = NULL;
  g_autofree char *cmd_str = bin2hex(cmd, cmd_size);
#endif

  g_assert(cmd);
  fp_dbg("CMD  -> 0x%02x - %s", cmd[0], cmd_to_str(cmd[0]));
#ifdef DEBUG
  fp_dbg("\traw req: %s", cmd_str);
#endif

  g_assert(self->cmd_ssm == NULL);
  self->cmd_ssm = fpi_ssm_new_full(device, synatlsmoc_cmd_run_state, CMD_STATES,
                                   CMD_STATES, "Cmd");

  fpi_ssm_set_data(self->cmd_ssm, data, g_free);
  data->callback = callback;
  data->raw = raw;
  data->check_res = check_res;

  if (self->session && !raw)
  {
    tls_session_wrap(self->session, cmd, cmd_size, &wrapped, &wrapped_len,
                     &local_error);
    if (local_error)
    {
      fpi_ssm_start(self->cmd_ssm, synatlsmoc_cmd_ssm_done);
      fpi_ssm_mark_failed(self->cmd_ssm,
                          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                               "Error while wrapping cmd: %s",
                                               local_error->message));
      g_error_free(local_error);
      return;
    }

    data->length_in = resp_size + WRAP_RESPONSE_ADDITIONAL_SIZE;

#ifdef DEBUG
    wrapped_str = bin2hex(wrapped, wrapped_len);
    fp_dbg("\traw wreq: %s", wrapped_str);
#endif
  }
  else
  {
    wrapped = g_memdup2(cmd, cmd_size);
    wrapped_len = cmd_size;
    data->length_in = resp_size;
  }

  FpiUsbTransfer *transfer = fpi_usb_transfer_new(device);
  // FIXME: why was this TRUE if we sometimes expect error messages?
  transfer->short_is_error = FALSE;
  transfer->ssm = self->cmd_ssm;

  fpi_usb_transfer_fill_bulk_full(transfer, SYNATLSMOC_EP_CMD_OUT, wrapped,
                                  wrapped_len, g_free);

  g_assert(self->cmd_transfer == NULL);
  self->cmd_transfer = transfer;
  fpi_ssm_start(self->cmd_ssm, synatlsmoc_cmd_ssm_done);
}

static void synatlsmoc_set_print_data(FpPrint *print, Db2Id *template_id,
                                      guint8 *user_id, guint8 finger_id)
{
  g_autofree gchar *user_id_safe =
      g_strndup((gchar *) user_id, WINBIO_SID_SIZE);

  fpi_print_fill_from_user_id(print, user_id_safe);
  fpi_print_set_type(print, FPI_PRINT_RAW);
  fpi_print_set_device_stored(print, TRUE);

  g_object_set(print, "description", user_id_safe, NULL);

  GVariant *uid = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, user_id_safe,
                                            WINBIO_SID_SIZE, 1);
  GVariant *tid = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, template_id,
                                            DB2_ID_SIZE, 1);

  GVariant *fpi_data = g_variant_new("(y@ay@ay)", finger_id, tid, uid);
  g_object_set(print, "fpi-data", fpi_data, NULL);
}

// FIXME: Is there a better place where to put communication functions?
/* here are communication functions sorted by value of cmd_id */
/* VCSFW_CMD_GET_VERSION =================================================== */

static gboolean fpi_byte_reader_get_mis_version(FpiByteReader *reader,
                                                MisVersion *result)
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
  read_ok &=
      fpi_byte_reader_get_data(reader, sizeof(result->serial_number), &to_copy);
  if (read_ok)
  {
    memcpy(result->serial_number, to_copy, sizeof(result->serial_number));
  }
  read_ok &= fpi_byte_reader_get_uint8(reader, &result->security);
  read_ok &= fpi_byte_reader_get_uint8(reader, &result->interface);
  /* skip over unknown8 */
  read_ok &= fpi_byte_reader_skip(reader, 8);
  read_ok &= fpi_byte_reader_get_uint16_le(reader, &result->device_type);
  /* skip over unknown1 */
  read_ok &= fpi_byte_reader_skip(reader, 1);
  read_ok &= fpi_byte_reader_get_uint8(reader, &result->provision_state);

  /* sanity check that all has been read */
  if (read_ok && (fpi_byte_reader_get_pos(reader) != 38))
  {
    fp_err("Invalid position when reading mis version: %d, expected: %d",
           fpi_byte_reader_get_pos(reader), 38);
    read_ok = FALSE;
  }

  return read_ok;
}

static void fp_dbg_mis_version(MisVersion *mis_version)
{
  g_autoptr(GDateTime) build_datetime =
      g_date_time_new_from_unix_utc(mis_version->build_time);
  g_autofree gchar *build_time_str = g_date_time_format_iso8601(build_datetime);
  g_autofree gchar *serial_number_str =
      bin2hex(mis_version->serial_number, sizeof(mis_version->serial_number));

  fp_dbg("Mis version data:");
  fp_dbg("\tBuild Time: %s", build_time_str);
  fp_dbg("\tBuild Num: %d", mis_version->build_num);
  fp_dbg("\tVersion: %d.%d", mis_version->version_major,
         mis_version->version_minor);
  fp_dbg("\tTarget: %d", mis_version->target);
  fp_dbg("\tProduct ID: %c", mis_version->product_id);
  fp_dbg("\tSilicon revision: %d", mis_version->silicon_revision);
  fp_dbg("\tFormal release: %d", mis_version->formal_release);
  fp_dbg("\tPlatform: %d", mis_version->platform);
  fp_dbg("\tPatch: %d", mis_version->patch);
  fp_dbg("\tSerial number: %s", serial_number_str);
  fp_dbg("\tSecurity: 0x%x", mis_version->security);
  fp_dbg("\tInterface: 0x%x", mis_version->interface);
  fp_dbg("\tDevice type: 0x%x", mis_version->device_type);
  fp_dbg("\tProvision state: %d", mis_version->provision_state);
}

static void recv_get_version(FpDevice *device, guchar *buffer_in,
                             gsize length_in, GError *error)
{
  fp_dbg("Receive get version callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;

  MisVersion mis_version;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  /* no need to read status again */
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_mis_version(&reader, &mis_version);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                             "Get version response too short"));
    return;
  }

  fp_dbg_mis_version(&mis_version);

  self->fw_version_major = mis_version.version_major;
  self->fw_version_minor = mis_version.version_minor;
  self->product = mis_version.product_id;
  self->security = mis_version.security;
  self->iface = mis_version.interface;
  self->provision_state = mis_version.provision_state;

  fpi_ssm_next_state(self->task_ssm);
}

static void send_get_version(FpiDeviceSynaTlsMoc *self)
{
  const guint send_size = 1;
  const guint resp_size = 38;

  guint8 cmd_buf[send_size];
  cmd_buf[0] = VCSFW_CMD_GET_VERSION;

  synatlsmoc_exec_cmd(self, FALSE, FALSE, cmd_buf, sizeof(cmd_buf), resp_size,
                      recv_get_version);
}

static void recv_get_version_tls_force_close(FpDevice *device,
                                             guchar *buffer_in, gsize length_in,
                                             GError *error)
{
  fp_dbg("Receive get version tls force close callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error != NULL)
  {
    goto error;
  }
  g_assert(buffer_in != NULL);

  /* deduced name */
  const guint16 unclosed_tls_session_status = 0x315;

  FpiByteReader reader;
  fpi_byte_reader_init(&reader, buffer_in, length_in);

  if (length_in < 2)
  {
    error = set_and_report_error(
        FP_DEVICE_ERROR_PROTO, "Response to get_version command was too short");
    goto error;
  }

  guint16 status = FP_READ_UINT16_LE(buffer_in);
  if (status_is_success(status))
  {
    fp_dbg("TLS force close - sensor was not in TLS session");
  }
  else if (status == unclosed_tls_session_status)
  {
    fp_dbg("TLS force close - sensor was in TLS status");
  }
  else
  {
    error = set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                 "Device responded with error: 0x%04x aka %s",
                                 status, status_to_str(status));
  }

error:
  if (error != NULL)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
  }
  else
  {
    /* start from begining to ensure tls was really closed */
    fpi_ssm_jump_to_state(self->task_ssm, OPEN_TLS_STATUS);
  }
}

/* Sends a get_version command to force the sensor to close its TLS
 session
 * -> error 0x315 is expected (its real name is not known) */
static void send_cmd_to_force_close_sensor_tls_session(
    FpiDeviceSynaTlsMoc *self)
{
  const guint send_size = 1;
  /* we may get a TLS alert message, so increase the recv_size accordingly */
  const guint expected_recv_size = 38 + WRAP_RESPONSE_ADDITIONAL_SIZE;

  guint8 cmd_buf[send_size];
  cmd_buf[0] = VCSFW_CMD_GET_VERSION;

  synatlsmoc_exec_cmd(self, FALSE, FALSE, cmd_buf, sizeof(cmd_buf),
                      expected_recv_size, recv_get_version_tls_force_close);
}

/* VCSFW_CMD_TLS_DATA ====================================================== */

static void recv_tls_data(FpDevice *device, guint8 *buffer_in, gsize length_in,
                          GError *error)
{
  fp_dbg("Receive TLS handshake callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  GError *local_error = NULL;
  if (!tls_session_receive_ciphertext(self->session, buffer_in, length_in,
                                      &local_error))
  {
    fpi_ssm_mark_failed(self->task_ssm, local_error);
  }

  if (tls_session_has_data(self->session))
  {
    fpi_ssm_jump_to_state(self->task_ssm, OPEN_TLS_SEND_DATA);
  }
  else
  {
    fpi_ssm_next_state(self->task_ssm);
  }
}

static void send_tls_data(FpiDeviceSynaTlsMoc *self, guint8 *tdata,
                          gsize tdata_size)
{
  const guint expected_recv_size = 256;

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init(&writer);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_TLS_DATA);
  /* padding ? */
  written &= fpi_byte_writer_fill(&writer, 0, 3);
  written &= fpi_byte_writer_put_data(&writer, tdata, tdata_size);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);

  gsize send_size = fpi_byte_writer_get_pos(&writer);
  g_autofree guint8 *send_data = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, TRUE, FALSE, send_data, send_size,
                      expected_recv_size, recv_tls_data);
}

/* VCSFW_CMD_FRAME_ACQ ===================================================== */

static void recv_frame_acquire(FpDevice *device, guint8 *buffer_in,
                               gsize length_in, GError *error)
{
  fp_dbg("Receive frame acquire callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  guint16 status = FP_READ_UINT16_LE(buffer_in);
  if (status_is_success(status))
  {
    fpi_ssm_next_state(self->task_ssm);
  }
  else if (status == RESPONSE_PROCESSING_FRAME)
  {
    gint *retry_idx;
    if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_ENROLL)
    {
      EnrollData *enroll_ssm_data = fpi_ssm_get_data(self->task_ssm);
      retry_idx = &enroll_ssm_data->frame_acquire_retry_idx;
    }
    else if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY)
    {
      VerifyIdentifyData *verify_identify_ssm_data =
          fpi_ssm_get_data(self->task_ssm);
      retry_idx = &verify_identify_ssm_data->frame_acquire_retry_idx;
    }
    else
    {
      g_assert_not_reached();
    }

    if (retry_idx > 0)
    {
      *retry_idx -= 1;
      fp_dbg("Received processing frame; current / max retries: %d/%d ....",
             *retry_idx, FRAME_ACQUIRE_NUM_RETRIES);
      fpi_ssm_jump_to_state(self->task_ssm, ENROLL_SEND_FRAME_ACQUIRE);
    }
    else
    {
      fpi_ssm_mark_failed(
          self->task_ssm,
          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                               "Frame acquire max retries reached"));
    }
  }
  else
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                             "Command failed with status: %s",
                                             status_to_str(status)));
  }
}

static void send_frame_acquire(FpiDeviceSynaTlsMoc *self, guint8 capture_flags)
{
  const guint send_size = 17;
  const guint expected_recv_size = SENSOR_FW_REPLY_STATUS_HEADER_LEN;

  fp_dbg("Frame acquire command");

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init(&writer);
  /* As there were only two capture flags used, I simplified the request logic
   * a bit */
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_FRAME_ACQ);
  /* I was unable to find the meaning of these values, so I did not abstract
   * them into constants */
  if (capture_flags == CAPTURE_FLAG_AUTH)
    written &= fpi_byte_writer_put_uint32_le(&writer, 4116);
  else
    written &= fpi_byte_writer_put_uint32_le(&writer, 12);
  written &= fpi_byte_writer_put_uint32_le(&writer, 1);  // Number of frames
  written &= fpi_byte_writer_put_uint16_le(&writer, 1);
  written &= fpi_byte_writer_put_uint8(&writer, 0);
  written &= fpi_byte_writer_put_uint8(&writer, 8);
  written &= fpi_byte_writer_put_uint8(&writer, 1);
  written &= fpi_byte_writer_put_uint8(&writer, 1);  // Trigger mode?
  written &= fpi_byte_writer_put_uint8(&writer, 1);
  written &= fpi_byte_writer_put_uint8(&writer, 0);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  /* Do not check the response status as there is a status on which we
   * should send the command again */
  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_frame_acquire);
}

/* VCSFW_CMD_FRAME_FINISH ================================================== */

static void sensor_frame_finish(FpiDeviceSynaTlsMoc *self)
{
  const guint send_size = 1;
  const guint expected_recv_size = SENSOR_FW_REPLY_STATUS_HEADER_LEN;
  fp_dbg("Frame finish command");

  guint8 cmd[send_size];
  cmd[0] = VCSFW_CMD_FRAME_FINISH;

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      synatlsmoc_ssm_next_state_cb);
}

/* VCSFW_CMD_EVENT_CONFIG ================================================== */

static void recv_event_config(FpDevice *device, guint8 *buffer_in,
                              gsize length_in, GError *error)
{
  fp_dbg("Receive event config callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;

  // Get current sequence number
  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, 64);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &self->event_seq_num);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO, "Cannot parse event data"));
    return;
  }

  fp_dbg("Current event sequence number: %d", self->event_seq_num);

  fpi_ssm_next_state(self->task_ssm);
}

static void send_event_config(FpiDeviceSynaTlsMoc *self, guint32 mask)
{
  const gint event_mask_cnt = 8;
  const guint send_size = 37;
  const guint expected_recv_size = 66;

  fp_dbg("Setting event mask to 0b%032b", mask);

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_EVENT_CONFIG);
  for (gint i = 0; i < event_mask_cnt && written; ++i)
  {
    written &= fpi_byte_writer_put_uint32_le(&writer, mask);
  }
  fpi_byte_writer_put_uint32_le(&writer, mask != 0 ? 0 : 4);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  // FIXME: should happen at the end of the callback
  self->event_mask = mask;
  self->event_recv = 0;

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_event_config);
}

/* VCSFW_CMD_EVENT_READ ==================================================== */

static void send_event_read(FpiDeviceSynaTlsMoc *self);

static void recv_event_read(FpDevice *device, guint8 *buffer_in,
                            gsize length_in, GError *error)
{
  fp_dbg("Recv event read");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  fpi_byte_reader_init(&reader, buffer_in, length_in);

  gboolean read_ok = TRUE;
  guint16 status;
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);

  if (read_ok && !status_is_success(status))
  {
    if (sensor_status_is_result_bad_param(status) &&
        (!self->event_read_in_legacy_mode))
    {
      fp_dbg(
          "\tReceived status 0x%04x on event read, falling back to "
          "legacy event reading -> sending event read again",
          status);
      self->event_read_in_legacy_mode = TRUE;
      send_event_read(self);
      return;
    }
    else
    {
      fpi_ssm_mark_failed(
          self->task_ssm,
          set_and_report_error(FP_DEVICE_ERROR_PROTO, "received status: 0x%04x",
                               status));
      return;
    }
  }

  guint16 recv_num_events, recv_num_pending_events;
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_events);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &recv_num_pending_events);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                             "Cannot parse event data 1"));
    return;
  }

  /* parse number of pending events */
  if (self->event_read_in_legacy_mode)
  {
    g_assert(recv_num_pending_events >= recv_num_events);
    self->num_pending_events = recv_num_pending_events - recv_num_events;
  }
  else
  {
    self->num_pending_events = recv_num_pending_events;
  }

  fp_dbg("\tNumber of events received: %d", recv_num_events);
  fp_dbg("\tNumber of events received+pending: %d", recv_num_pending_events);

  self->event_seq_num = (self->event_seq_num + recv_num_events) & 0xFFFF;
  fp_dbg("\tNew event sequence number: %d", self->event_seq_num);

  // Parse events
  fp_dbg("\tReceived events:");
  for (int i = 0; i < recv_num_events && read_ok; i++)
  {
    guint8 event_type;
    read_ok &= fpi_byte_reader_get_uint8(&reader, &event_type);
    /* skip over unknown */
    read_ok &= fpi_byte_reader_skip(&reader, 11);

    if (!read_ok)
    {
      fpi_ssm_mark_failed(self->task_ssm,
                          set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                               "Cannot parse event data 2"));
      return;
    }

    fp_dbg("\t\t%d = %s", event_type, event_type_to_str(event_type));

    self->event_recv |= (1 << event_type);
  }

  if (self->num_pending_events > 0)
  {
    fp_dbg("\tThere are %u events pending -> sending event read again",
           self->num_pending_events);
    send_event_read(self);
  }
  else if (self->event_recv == self->event_mask)
  {
    fpi_ssm_next_state(self->task_ssm);
  }
  else
  {
    fpi_ssm_jump_to_state(self->task_ssm,
                          fpi_ssm_get_cur_state(self->task_ssm));
  }
}

static void send_event_read(FpiDeviceSynaTlsMoc *self)
{
  fp_dbg("Send event read");
  const guint16 max_num_events_in_resp = 32;

  const guint send_size = self->event_read_in_legacy_mode ? 5 : 9;
  const guint expected_recv_size = 6 + 12 * max_num_events_in_resp;

  FpiByteWriter writer;
  gboolean written = TRUE;

  g_autofree guint8 *cmd = NULL;

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_EVENT_READ);
  written &= fpi_byte_writer_put_uint16_le(&writer, self->event_seq_num);
  written &= fpi_byte_writer_put_uint16_le(&writer, max_num_events_in_resp);
  if (!self->event_read_in_legacy_mode)
    written &= fpi_byte_writer_put_uint32_le(&writer, 1);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  cmd = fpi_byte_writer_reset_and_get_data(&writer);

  /* do not check status in response, as we may want to switch to legacy event
   * reading based on it */
  synatlsmoc_exec_cmd(self, FALSE, FALSE, cmd, send_size, expected_recv_size,
                      recv_event_read);
}

/* VCSFW_CMD_PAIR ========================================================== */

static void recv_pair(FpDevice *device, guchar *buffer_in, gsize length_in,
                      GError *error)
{
  fp_dbg("Receive pair");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error != NULL)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  fpi_byte_reader_init(&reader, buffer_in, length_in);

  gboolean read_ok = TRUE;
  /* no need to read status again */
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);

  if (read_ok && self->pairing_data.client_cert_raw != 0)
  {
    fp_warn("Overwriting stored client/host certificate");
    g_free(self->pairing_data.client_cert_raw);
  }
  if (read_ok) self->pairing_data.client_cert_len = CERTIFICATE_SIZE;
  read_ok &= fpi_byte_reader_dup_data(&reader, CERTIFICATE_SIZE,
                                      &self->pairing_data.client_cert_raw);

  if (read_ok && self->pairing_data.server_cert_raw != 0)
  {
    fp_warn("Overwriting stored server/sensor certificate");
    g_free(self->pairing_data.server_cert_raw);
  }
  read_ok &= fpi_byte_reader_dup_data(&reader, CERTIFICATE_SIZE,
                                      &self->pairing_data.server_cert_raw);
  if (read_ok) self->pairing_data.server_cert_len = CERTIFICATE_SIZE;

  if (!parse_certificates_within_self(self, &error))
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }
  // FIXME: private key should exist at this point
  g_assert(self->pairing_data.client_key != NULL);

  fpi_ssm_next_state(self->task_ssm);
}

/* NOTE: size of send_host_cert_bytes is expected to be CERTIFICATE_SIZE
 */
static void send_pair(FpiDeviceSynaTlsMoc *self,
                      const guint8 *send_host_cert_bytes)
{
  g_assert(send_host_cert_bytes != NULL);

  const guint send_size = 1 + CERTIFICATE_SIZE;
  const guint expected_recv_size =
      SENSOR_FW_REPLY_STATUS_HEADER_LEN + 2 * CERTIFICATE_SIZE;

  fp_dbg("Pair command");

  FpiByteWriter writer;
  gboolean written = TRUE;
  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_PAIR);
  fpi_byte_writer_put_data(&writer, send_host_cert_bytes, CERTIFICATE_SIZE);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_pair);
}

/* VCSFW_CMD_ENROLL ======================================================== */

static void recv_enroll_start(FpDevice *device, guint8 *buffer_in,
                              gsize length_in, GError *error)
{
  fp_dbg("Receive enroll start callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint32 nonce_size;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  /* no need to read status again */
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &nonce_size);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "Cannot parse enroll start response"));
    return;
  }

  // NOTE: nonce buffer is not used
  fp_dbg("Received nonce buffer with size: %d", nonce_size);

  fpi_ssm_next_state(self->task_ssm);
}

static void send_enroll_start(FpiDeviceSynaTlsMoc *self)
{
  /* unused parameter of original function */
  const guint32 nonce_buffer_size = 0;

  const guint send_size = 13;
  const guint expected_recv_size = 6 + nonce_buffer_size;

  fp_dbg("Enroll start command");

  FpiByteWriter writer;
  gboolean written = TRUE;
  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
  fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_START);
  fpi_byte_writer_put_uint32_le(&writer, nonce_buffer_size != 0);
  fpi_byte_writer_put_uint32_le(&writer, nonce_buffer_size);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_enroll_start);
}

static void fp_dbg_enroll_stats(EnrollStats *enroll_stats)
{
  fp_dbg("Enroll stats:");
  fp_dbg("\tprogress: %d", enroll_stats->progress);
  fp_dbg("\tquality: %d", enroll_stats->quality);
  fp_dbg("\tredundant: %d", enroll_stats->redundant);
  fp_dbg("\trejected: %d", enroll_stats->rejected);
  fp_dbg("\ttemplate count: %d", enroll_stats->template_cnt);
  fp_dbg("\tenroll quality: %d", enroll_stats->enroll_quality);
  fp_dbg("\tenroll status: %d", enroll_stats->status);
  fp_dbg("\t(smt like) has fixed pattern: %d", enroll_stats->has_fixed_pattern);
}

static gboolean fpi_byte_reader_get_enroll_stats(FpiByteReader *reader,
                                                 EnrollStats *enroll_stats)
{
  gboolean read_ok = TRUE;

  /* skip over unknown */
  read_ok &= fpi_byte_reader_skip(reader, 2);
  read_ok &= fpi_byte_reader_get_uint16_le(reader, &enroll_stats->progress);
  /* not reading template id as it is sometimes missing */
  read_ok &= fpi_byte_reader_skip(reader, DB2_ID_SIZE);
  read_ok &= fpi_byte_reader_get_uint32_le(reader, &enroll_stats->quality);
  read_ok &= fpi_byte_reader_get_uint32_le(reader, &enroll_stats->redundant);
  read_ok &= fpi_byte_reader_get_uint32_le(reader, &enroll_stats->rejected);
  /* skip over unknown */
  read_ok &= fpi_byte_reader_skip(reader, 4);
  read_ok &= fpi_byte_reader_get_uint32_le(reader, &enroll_stats->template_cnt);
  read_ok &=
      fpi_byte_reader_get_uint16_le(reader, &enroll_stats->enroll_quality);
  /* skip over unknown */
  read_ok &= fpi_byte_reader_skip(reader, 6);
  read_ok &= fpi_byte_reader_get_uint32_le(reader, &enroll_stats->status);
  /* skip over unknown */
  read_ok &= fpi_byte_reader_skip(reader, 4);
  read_ok &=
      fpi_byte_reader_get_uint32_le(reader, &enroll_stats->has_fixed_pattern);

  return read_ok;
}

static void recv_add_image(FpDevice *device, guint8 *buffer_in, gsize length_in,
                           GError *error)
{
  fp_dbg("Receive add image callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  EnrollData *data = fpi_ssm_get_data(self->task_ssm);
  FpiByteReader reader;
  gboolean read_ok = TRUE;
  g_autofree guint8 *template_id = NULL;
  guint32 qm_struct_size;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  /* no need to read status again */
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_dup_data(&reader, DB2_ID_SIZE, &template_id);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &qm_struct_size);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm, set_and_report_error(
                                            FP_DEVICE_ERROR_PROTO,
                                            "Cannot parse add image response"));
    return;
  }

  if (qm_struct_size != 60)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(
            FP_DEVICE_ERROR_PROTO,
            "qm struct size is not valid: got %d bytes instead of 60",
            qm_struct_size));
    return;
  }

  EnrollStats enroll_stats;
  read_ok &= fpi_byte_reader_get_enroll_stats(&reader, &enroll_stats);
  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

  fp_dbg_enroll_stats(&enroll_stats);
  g_autofree gchar *template_id_str = bin2hex(template_id, DB2_ID_SIZE);
  fp_dbg("\ttemplate id: %s", template_id_str);

  GError *retry = NULL;

  if (enroll_stats.rejected != 0)
  {
    if (enroll_stats.redundant != 0)
    {
      fp_info("Image rejected due to being redundant");
      retry = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                       "Scan is redundant");
    }
    else if (enroll_stats.has_fixed_pattern != 0)
    {
      fp_info("Image rejected due to fixed pattern");
      retry = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                       "Scan has fixed pattern");
    }
    else
    {
      fp_info("Image rejected due to bad quality: %d", enroll_stats.quality);
      retry = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL,
                                       "Scan has bad quality");
    }
  }

  fpi_device_enroll_progress(device, enroll_stats.template_cnt, NULL, retry);

  if (enroll_stats.progress == 100)
  {
    fp_dbg("Enrollment completed successfully with quality %d",
           enroll_stats.quality);

    data->template_id = g_steal_pointer(&template_id);

    fpi_ssm_next_state(self->task_ssm);
  }
  else
  {
    fpi_ssm_jump_to_state(self->task_ssm, ENROLL_SET_EVENT_FINGER_UP);
  }
}

static void send_add_image(FpiDeviceSynaTlsMoc *self)
{
  fp_dbg("Add image command");
  const guint send_size = 5;
  const guint expected_recv_size = 82;

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
  written &= fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_ADD_IMAGE);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_add_image);
}

static void send_enroll_commit(FpiDeviceSynaTlsMoc *self,
                               guint8 *enroll_commit_data,
                               gsize enroll_commit_data_size)
{
  fp_dbg("Enroll commit command");
  g_assert((enroll_commit_data_size != 0) && (enroll_commit_data != NULL));

  const guint send_size = 13 + enroll_commit_data_size;
  const guint expected_recv_size = SENSOR_FW_REPLY_STATUS_HEADER_LEN;

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
  written &= fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_COMMIT);
  written &= fpi_byte_writer_put_uint32_le(&writer, 0);
  written &= fpi_byte_writer_put_uint32_le(&writer, enroll_commit_data_size);
  written &= fpi_byte_writer_put_data(&writer, enroll_commit_data,
                                      enroll_commit_data_size);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      synatlsmoc_ssm_next_state_cb);
}

static void send_enroll_finish(FpiDeviceSynaTlsMoc *self)
{
  fp_dbg("Enroll finish command");
  const guint send_size = 5;
  const guint expected_recv_size = SENSOR_FW_REPLY_STATUS_HEADER_LEN;

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_ENROLL);
  written &= fpi_byte_writer_put_uint32_le(&writer, ENROLL_SUBCMD_FINISH);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      synatlsmoc_ssm_next_state_cb);
}

/* VCSFW_CMD_IDENTIFY_MATCH ================================================ */

static void recv_identify_match_cb(FpDevice *device, guint8 *buffer_in,
                                   gsize length_in, GError *error)
{
  fp_dbg("Receive identify match callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  GError *local_error = NULL;
  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint16 status;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &status);

  // Should have no way of failing
  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

  /* we get VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 if we send
   * template_ids_to_match and VCS_RESULT_MATCHER_MATCH_FAILED otherwise
   */
  if (status == VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 ||
      status == VCS_RESULT_MATCHER_MATCH_FAILED)
  {
    fp_info("Print was not identified by the device");

    if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_IDENTIFY)
    {
      fpi_device_identify_report(device, NULL, NULL, NULL);
    }
    else
    {
      fpi_device_verify_report(device, FPI_MATCH_FAIL, NULL, NULL);
    }

    fpi_ssm_next_state(self->task_ssm);
    return;
  }

  if (!status_is_success(status))
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                             "Command failed with status: %s",
                                             status_to_str(status)));
    return;
  }

  guint32 qm_struct_size;
  const guint8 *qm_struct;
  guint32 y_len, z_len;
  g_autofree guint8 *z_data = NULL;
  guint32 match_score;
  guint8 *user_id, *finger_id;
  Db2Id *template_id;
  gsize template_id_len, user_id_len, finger_id_len;

  read_ok &= fpi_byte_reader_skip(&reader, DB2_ID_SIZE);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &qm_struct_size);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &y_len);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &z_len);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

  if (qm_struct_size != 36)
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(
                            FP_DEVICE_ERROR_PROTO,
                            "qm_struct size mismatch: expected=36, received=%d",
                            qm_struct_size));
    return;
  }

  if (y_len != 0 || z_len == 0)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(
            FP_DEVICE_ERROR_PROTO,
            "Unsupported identify match response: y_len=%d, z_len=%d", y_len,
            z_len));
    return;
  }

  read_ok &= fpi_byte_reader_get_data(&reader, qm_struct_size, &qm_struct);
  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

  match_score = FP_READ_UINT32_LE(qm_struct);
  if (match_score == 0) fp_warn("Match score is 0");

  read_ok &= fpi_byte_reader_dup_data(&reader, z_len, &z_data);
  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

  g_autoptr(TagVal) tagval = NULL;
  gboolean tagval_ok = TRUE;
  tagval_ok &= tagval_new_from_bytes(&tagval, z_data, z_len, &local_error);
  tagval_ok &=
      tagval_get(tagval, ENROLL_TAG_TEMPLATE_ID, (guint8 **) &template_id,
                 &template_id_len, &local_error);
  tagval_ok &= tagval_get(tagval, ENROLL_TAG_USER_ID, &user_id, &user_id_len,
                          &local_error);
  tagval_ok &= tagval_get(tagval, ENROLL_TAG_FINGER_ID, &finger_id,
                          &finger_id_len, &local_error);

  if (!tagval_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm, local_error);
    return;
  }

  g_assert(template_id_len == DB2_ID_SIZE);
  g_assert(user_id_len == WINBIO_SID_SIZE);
  g_assert(finger_id_len == sizeof(guint8));

  /* Create a new print from template_id, user_id and finger_id and then see
   * if it matches the one indicated */
  FpPrint *print = fp_print_new(device);
  synatlsmoc_set_print_data(print, template_id, user_id, *finger_id);

  fp_info("Identify successful for: %s", fp_print_get_description(print));

  if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_IDENTIFY)
  {
    GPtrArray *prints;
    gboolean found = FALSE;
    guint index;

    fpi_device_get_identify_data(device, &prints);
    found = g_ptr_array_find_with_equal_func(
        prints, print, (GEqualFunc) fp_print_equal, &index);

    if (found)
      fpi_device_identify_report(device, g_ptr_array_index(prints, index),
                                 print, NULL);
    else
      fpi_device_identify_report(device, NULL, print, NULL);
  }
  else
  {
    FpPrint *verify_print = NULL;
    fpi_device_get_verify_data(device, &verify_print);
    fp_info("Verifying against: %s", fp_print_get_description(verify_print));

    if (fp_print_equal(verify_print, print))
      fpi_device_verify_report(device, FPI_MATCH_SUCCESS, print, NULL);
    else
      fpi_device_verify_report(device, FPI_MATCH_FAIL, print, NULL);
  }

  fpi_ssm_next_state(self->task_ssm);
}

static void send_identify_match(FpiDeviceSynaTlsMoc *self,
                                Db2Id *template_ids_to_match,
                                guint template_id_cnt)
{
  fp_dbg("Identify match command");

  /* unused function argument */
  const gsize data_2_size = 0;
  const guint8 *data_2 = NULL;

  /* send only one type of data */
  g_assert(((data_2_size == 0) && (data_2 == NULL)) ||
           ((template_id_cnt == 0) && (template_ids_to_match == 0)));

  const gsize template_id_array_size =
      sizeof(*template_ids_to_match) * template_id_cnt;

  const guint send_size = 13 + data_2_size + template_id_array_size;
  const guint expected_recv_size = 1602;

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init(&writer);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_IDENTIFY_MATCH);
  written &=
      fpi_byte_writer_put_uint32_le(&writer, IDENTIFY_MATCH_SUBCMD_WBF_MATCH);
  written &= fpi_byte_writer_put_uint32_le(&writer, template_id_array_size);
  written &= fpi_byte_writer_put_uint32_le(&writer, data_2_size);
  if (template_ids_to_match != NULL)
  {
    fpi_byte_writer_put_data(&writer, *template_ids_to_match,
                             template_id_cnt * template_id_array_size);
  }
  else if (data_2 != NULL)
  {
    fpi_byte_writer_put_data(&writer, data_2, data_2_size);
  }

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, FALSE, cmd, send_size, expected_recv_size,
                      recv_identify_match_cb);
}

/* VCSFW_CMD_GET_IMAGE_METRICS ============================================= */

static void recv_get_image_metrics(FpDevice *device, guint8 *buffer_in,
                                   gsize length_in, GError *error)
{
  fp_dbg("Receive image metrics callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint32 image_metrics_length, image_metrics_type;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &image_metrics_type);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &image_metrics_length);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(
            FP_DEVICE_ERROR_PROTO,
            "The requested image metrics aren't supported by the sensor"));
    return;
  }

  if (image_metrics_length == 0)
  {
    fp_warn("Unable to query image metrics now");
  }
  else
  {
    switch (image_metrics_type)
    {
      case MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE:
        g_assert(image_metrics_length == 4);

        guint32 ipl_coverage;
        read_ok &= fpi_byte_reader_get_uint32_le(&reader, &ipl_coverage);
        FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

        fp_dbg("IPL finger coverage: %u", ipl_coverage);
        break;
      case MIS_IMAGE_METRICS_IMG_QUALITY:
        g_assert(image_metrics_length == 8);

        guint32 matcher_img_quality, matcher_sensor_coverage;
        read_ok &= fpi_byte_reader_get_uint32_le(&reader, &matcher_img_quality);
        read_ok &=
            fpi_byte_reader_get_uint32_le(&reader, &matcher_sensor_coverage);
        FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

        fp_dbg("Matcher image quality: %d%%", matcher_img_quality);
        fp_dbg("Matcher sensor coverage: %d%%", matcher_sensor_coverage);

        if (matcher_img_quality < IMAGE_QUALITY_THRESHOLD)
        {
          fpi_ssm_mark_failed(
              self->task_ssm,
              set_and_report_error(
                  FP_DEVICE_ERROR_GENERAL,
                  "Image quality %d%% is lower than threshold %d%%",
                  matcher_img_quality, IMAGE_QUALITY_THRESHOLD));
          return;
        }

        break;
      default:
        fpi_ssm_mark_failed(
            self->task_ssm,
            set_and_report_error(
                FP_DEVICE_ERROR_PROTO,
                "Received unknown image metrics: type=0x%08x, length=%d",
                image_metrics_type, image_metrics_length));
        return;
    }
  }

  fpi_ssm_next_state(self->task_ssm);
}

static void send_get_image_metrics(FpiDeviceSynaTlsMoc *self,
                                   ImageMetricsType type)
{
  fp_dbg("Image metrics command");

  FpiByteWriter writer;
  gboolean written = TRUE;

  const guint send_size = 5;
  guint expected_recv_size;

  switch (type)
  {
    case MIS_IMAGE_METRICS_IMG_QUALITY: expected_recv_size = 70; break;
    case MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE: expected_recv_size = 14; break;
    default:
      expected_recv_size = 10;
      fp_warn("Default reached when switching image metrics types with: %d",
              type);
      break;
  }

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_GET_IMAGE_METRICS);
  written &= fpi_byte_writer_put_uint32_le(&writer, type);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_get_image_metrics);
}

/* VCSFW_CMD_GET_DB2_INFO ================================================== */
static gboolean fpi_byte_reader_get_db2_info(FpiByteReader *reader,
                                             Db2Info *db2_info)
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
  read_ok &= fpi_byte_reader_get_uint16_le(reader,
                                           &db2_info->payload_object_slot_size);
  read_ok &=
      fpi_byte_reader_get_uint16_le(reader, &db2_info->num_current_users);
  read_ok &=
      fpi_byte_reader_get_uint16_le(reader, &db2_info->num_deleted_users);
  read_ok &= fpi_byte_reader_get_uint16_le(reader,
                                           &db2_info->num_available_user_slots);
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

static void fp_dbg_db2_info(Db2Info *db2_info)
{
  fp_dbg("received DB2 info:");
  fp_dbg("\tdummy: %d", db2_info->dummy);
  fp_dbg("\tDB2 version: %d.%d", db2_info->version_major,
         db2_info->version_minor);
  fp_dbg("\tpartition_version: %d", db2_info->partition_version);
  fp_dbg("\tuop_length: %d", db2_info->uop_length);
  fp_dbg("\ttop_length: %d", db2_info->top_length);
  fp_dbg("\tpop_length: %d", db2_info->pop_length);
  fp_dbg("\ttemplate_object_size: %d", db2_info->template_object_size);
  fp_dbg("\tpayload_object_slot_size: %d", db2_info->payload_object_slot_size);
  fp_dbg("\tUsers (current/deleted/available): %d/%d/%d",
         db2_info->num_current_users, db2_info->num_deleted_users,
         db2_info->num_available_user_slots);
  fp_dbg("\tTemplates (current/deleted/available): %d/%d/%d",
         db2_info->num_current_templates, db2_info->num_deleted_templates,
         db2_info->num_available_template_slots);
  fp_dbg("\tPayloads (current/deleted/available): %d/%d/%d",
         db2_info->num_current_payloads, db2_info->num_deleted_payloads,
         db2_info->num_available_payload_slots);
}

static void recv_db2_get_db2_info(FpDevice *device, guint8 *buffer_in,
                                  gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 info callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  ListData *data = fpi_ssm_get_data(self->task_ssm);

  FpiByteReader reader;
  gboolean read_ok = TRUE;

  Db2Info db2_info;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_db2_info(&reader, &db2_info);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "Response to get DB2 info was too short"));
    return;
  }

  fp_dbg_db2_info(&db2_info);

  data->num_current_users = db2_info.num_current_users;
  data->num_current_templates = db2_info.num_current_templates;
  data->num_current_payloads = db2_info.num_current_payloads;

  data->cleanup_required =
      db2_info.num_deleted_users != 0 && db2_info.num_available_user_slots == 0;

  fpi_ssm_next_state(self->task_ssm);
}

/* prints DB2 info on debug output and stores numbers of current users,
 * templates and payloads */
static void send_db2_info(FpiDeviceSynaTlsMoc *self)
{
  const guint send_size = 2;
  const guint expected_recv_size = 64;

  guint8 send_data[send_size];
  send_data[0] = VCSFW_CMD_DB2_GET_DB_INFO;
  send_data[1] = 0x01;

  synatlsmoc_exec_cmd(self, FALSE, TRUE, send_data, send_size,
                      expected_recv_size, recv_db2_get_db2_info);
}

/* VCSFW_CMD_GET_OBJECT_LIST =============================================== */

static gsize get_object_list_recv_size(FpiDeviceSynaTlsMoc *self,
                                       ObjType obj_type)
{
  ListData *data = fpi_ssm_get_data(self->task_ssm);

  switch (obj_type)
  {
    case OBJ_TYPE_USERS: return 4 + 16 * data->num_current_users; break;
    case OBJ_TYPE_TEMPLATES: return 4 + 16 * data->num_current_templates; break;
    case OBJ_TYPE_PAYLOADS: return 4 + 16 * data->num_current_payloads; break;
    default:
      fp_err("Unknown object type: %d", obj_type);
      g_assert_not_reached();
      break;
  }

  return 0;
}

static void recv_db2_get_template_list(FpDevice *device, guint8 *buffer_in,
                                       gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 template list callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  ListData *data = fpi_ssm_get_data(self->task_ssm);

  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint16 num_templates;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_templates);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);
  fp_dbg(
      "Received object list of obj_type OBJ_TYPE_TEMPLATES with %d elements:",
      num_templates);

  for (int i = 0; i < num_templates && read_ok; i++)
  {
    g_autofree guint8 *template_id = NULL;
    fpi_byte_reader_dup_data(&reader, DB2_ID_SIZE, &template_id);

    FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);
    g_autofree gchar *template_str = bin2hex(template_id, DB2_ID_SIZE);
    fp_dbg("\tat idx %d is: %s", i, template_str);

    g_ptr_array_add(data->list_template_id, g_steal_pointer(&template_id));
  }

  if (data->list_template_id->len == 0)
  {
    fp_dbg("Received empty tuid list");
    fpi_ssm_jump_to_state(self->task_ssm, LIST_REPORT);
  }
  else
  {
    fpi_ssm_next_state(self->task_ssm);
  }
}

static void recv_db2_get_payload_list(FpDevice *device, guint8 *buffer_in,
                                      gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 payload list callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  ListData *data = fpi_ssm_get_data(self->task_ssm);

  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint16 num_payloads;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_payloads);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);
  fp_dbg("Received object list of obj_type OBJ_TYPE_PAYLOADS with %d elements ",
         num_payloads);

  for (int i = 0; i < num_payloads && read_ok; i++)
  {
    g_autofree guint8 *payload = NULL;
    fpi_byte_reader_dup_data(&reader, DB2_ID_SIZE, &payload);

    FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);
    g_autofree gchar *payload_str = bin2hex(payload, DB2_ID_SIZE);
    fp_dbg("\tat idx %d is: %s", i, payload_str);

    g_ptr_array_add(data->list_payload_id, g_steal_pointer(&payload));
  }

  if (data->list_payload_id->len == 0)
  {
    g_autofree gchar *tuid_str =
        bin2hex((guint8 *) data->current_template_id, DB2_ID_SIZE);
    fp_dbg("No payload data for an enrollment with tuid: %s", tuid_str);

    if (data->list_template_id->len > 0)
      fpi_ssm_jump_to_state(self->task_ssm, LIST_DB2_GET_PAYLOAD_LIST);
    else
      fpi_ssm_jump_to_state(self->task_ssm, LIST_REPORT);
  }
  else
  {
    fpi_ssm_next_state(self->task_ssm);
  }
}

/* NOTE: the current number of items in db2 database needs to be up to date when
 * calling this function */
static void send_db2_get_object_list(FpiDeviceSynaTlsMoc *self,
                                     const ObjType obj_type, const Db2Id obj_id)
{
  const guint send_size = 21;
  const guint expected_recv_size = get_object_list_recv_size(self, obj_type);

  g_autofree char *obj_id_str = bin2hex(obj_id, DB2_ID_SIZE);
  fp_dbg("Getting object list of type %s for id: %s", obj_type_to_str(obj_type),
         obj_id_str);

  FpiByteWriter writer;
  gboolean written = TRUE;
  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_GET_OBJECT_LIST);
  fpi_byte_writer_put_uint32_le(&writer, obj_type);
  fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  CmdCallback callback;
  switch (obj_type)
  {
    case OBJ_TYPE_PAYLOADS: callback = recv_db2_get_payload_list; break;
    case OBJ_TYPE_TEMPLATES: callback = recv_db2_get_template_list; break;
    case OBJ_TYPE_USERS:
    default: g_assert_not_reached();
  }

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      callback);
}

/* VCSFW_CMD_GET_OBJECT_INFO =============================================== */

static void recv_db2_get_payload_info(FpDevice *device, guint8 *buffer_in,
                                      gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 payload info callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  ListData *data = fpi_ssm_get_data(self->task_ssm);

  FpiByteReader reader;
  gboolean read_ok = TRUE;

  g_autofree guint8 *info_0_1 = NULL, *info_2_17 = NULL, *info_18_33 = NULL,
                    *info_34_45 = NULL;
  guint32 payload_size;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_dup_data(&reader, 2, &info_0_1);
  read_ok &= fpi_byte_reader_dup_data(&reader, 16, &info_2_17);
  read_ok &= fpi_byte_reader_dup_data(&reader, 16, &info_18_33);
  read_ok &= fpi_byte_reader_dup_data(&reader, 12, &info_34_45);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &payload_size);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "Response to get payload info was too short"));
    return;
  }

  g_autofree gchar *info_0_1_str = bin2hex(info_0_1, 2);
  g_autofree gchar *info_2_17_str = bin2hex(info_2_17, 16);
  g_autofree gchar *info_18_33_str = bin2hex(info_18_33, 16);
  g_autofree gchar *info_34_45_str = bin2hex(info_34_45, 12);
  fp_dbg("DB2 payload info:");
  fp_dbg("\t0-1: %s", info_0_1_str);
  fp_dbg("\t2-17: %s", info_2_17_str);
  fp_dbg("\t18-33: %s", info_18_33_str);
  fp_dbg("\t34-45: %s", info_34_45_str);
  fp_dbg("\t46-49 size of payload data: %d", payload_size);

  data->current_payload_size = payload_size;

  fpi_ssm_next_state(self->task_ssm);
}

static void recv_db2_get_template_info(FpDevice *device, guint8 *buffer_in,
                                       gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 template info callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  DeleteData *data = fpi_ssm_get_data(self->task_ssm);

  FpiByteReader reader;
  gboolean read_ok = TRUE;

  g_autofree guint8 *info_0_1 = NULL, *info_18_33 = NULL, *info_34_45 = NULL;
  guint32 some_size;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  /* no need to read status again */
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_dup_data(&reader, 2, &info_0_1);
  const guint8 *user_id_offset;
  read_ok &= fpi_byte_reader_get_data(&reader, DB2_ID_SIZE, &user_id_offset);
  if (read_ok) memcpy(data->user_id, user_id_offset, DB2_ID_SIZE);
  read_ok &= fpi_byte_reader_dup_data(&reader, 16, &info_18_33);
  read_ok &= fpi_byte_reader_dup_data(&reader, 12, &info_34_45);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &some_size);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(
                            FP_DEVICE_ERROR_PROTO,
                            "Response to DB2 get template info was too short"));
    return;
  }

  g_autofree gchar *info_0_1_str = bin2hex(info_0_1, 2);
  g_autofree gchar *user_id_str = bin2hex(data->user_id, DB2_ID_SIZE);
  g_autofree gchar *info_18_33_str = bin2hex(info_18_33, 16);
  g_autofree gchar *info_34_45_str = bin2hex(info_34_45, 12);
  fp_dbg("DB2 payload info:");
  fp_dbg("\t0-1: %s", info_0_1_str);
  fp_dbg("\t2-17 user_id: %s", user_id_str);
  fp_dbg("\t18-33: %s", info_18_33_str);
  fp_dbg("\t34-45: %s", info_34_45_str);
  fp_dbg("\t46-49: %d", some_size);

  fpi_ssm_next_state(self->task_ssm);
}

static void send_db2_get_object_info(FpiDeviceSynaTlsMoc *self,
                                     const ObjType obj_type, const Db2Id obj_id)
{
  const guint send_size = 21;
  const guint expected_recv_size = obj_type == OBJ_TYPE_USERS ? 12 : 52;

  g_autofree gchar *obj_id_str = bin2hex(obj_id, DB2_ID_SIZE);
  fp_dbg("Getting object info for %s with id: %s", obj_type_to_str(obj_type),
         obj_id_str);

  FpiByteWriter writer;
  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

  gboolean written = TRUE;
  fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_GET_OBJECT_INFO);
  fpi_byte_writer_put_uint32_le(&writer, obj_type);
  fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  CmdCallback callback;
  switch (obj_type)
  {
    case OBJ_TYPE_PAYLOADS: callback = recv_db2_get_payload_info; break;
    case OBJ_TYPE_TEMPLATES: callback = recv_db2_get_template_info; break;
    case OBJ_TYPE_USERS:
    default: g_assert_not_reached();
  }

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      callback);
}

/* VCSFW_CMD_GET_OBJECT_DATA =============================================== */

static void recv_db2_get_payload_data(FpDevice *device, guint8 *buffer_in,
                                      gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 payload data callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  ListData *data = fpi_ssm_get_data(self->task_ssm);

  GError *local_error = NULL;
  FpiByteReader reader;
  gboolean read_ok = TRUE;
  gboolean tagval_ok = TRUE;

  guint32 payload_size = 0;
  g_autofree guint8 *payload_data = NULL;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, 4);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &payload_size);
  read_ok &= fpi_byte_reader_dup_data(&reader, payload_size, &payload_data);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                             "Cannot parse DB2 payload data"));
    return;
  }

  g_assert(fpi_byte_reader_get_remaining(&reader) == 0);

  g_autoptr(TagVal) tagval = NULL;
  if (!tagval_new_from_bytes(&tagval, payload_data, payload_size, &local_error))
  {
    fpi_ssm_mark_failed(self->task_ssm, local_error);
    return;
  }

  guint8 *user_id, *finger_id;
  Db2Id *template_id;
  gsize template_id_len, user_id_len, finger_id_len;

  tagval_ok &=
      tagval_get(tagval, ENROLL_TAG_TEMPLATE_ID, (guint8 **) &template_id,
                 &template_id_len, &local_error);
  tagval_ok &= tagval_get(tagval, ENROLL_TAG_USER_ID, &user_id, &user_id_len,
                          &local_error);
  tagval_ok &= tagval_get(tagval, ENROLL_TAG_FINGER_ID, &finger_id,
                          &finger_id_len, &local_error);
  if (!tagval_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm, local_error);
    return;
  }

  g_assert(template_id_len == DB2_ID_SIZE);
  g_assert(user_id_len == WINBIO_SID_SIZE);
  g_assert(finger_id_len == sizeof(guint8));

  g_autofree gchar *tuid_str =
      bin2hex((guint8 *) data->current_template_id, DB2_ID_SIZE);
  g_autofree gchar *payload_id_str =
      bin2hex((guint8 *) data->current_payload_id, DB2_ID_SIZE);
  g_autofree gchar *template_id_str =
      bin2hex((guint8 *) template_id, template_id_len);
  fp_dbg("Object with tuid=%s and payload_id=%s has data:", tuid_str,
         payload_id_str);
  fp_dbg("\ttemplate_id: %s", template_id_str);
  fp_dbg("\tuser_id: \"%s\"", user_id);
  fp_dbg("\tfinger_id: %d", *finger_id);

  FpPrint *print = fp_print_new(device);
  synatlsmoc_set_print_data(print, template_id, user_id, *finger_id);
  g_ptr_array_add(data->list_result, g_object_ref_sink(print));

  if (data->list_template_id->len > 0)
    fpi_ssm_jump_to_state(self->task_ssm, LIST_DB2_GET_PAYLOAD_LIST);
  else
    fpi_ssm_next_state(self->task_ssm);
}

static void send_db2_get_object_data(FpiDeviceSynaTlsMoc *self,
                                     const ObjType obj_type, const Db2Id obj_id,
                                     gsize obj_data_size)
{
  g_assert(obj_data_size < 65535);

  const guint send_size = 21;
  guint expected_recv_size;

  if (obj_type == OBJ_TYPE_USERS)
  {
    expected_recv_size = 8;
    fp_warn("DB2 get object data is untested for OBJ_TYPE_USERS");
  }
  else
  {
    expected_recv_size = 8 + obj_data_size;
  }

  g_autofree gchar *obj_id_str = bin2hex(obj_id, DB2_ID_SIZE);
  fp_dbg("Getting object data for %s with id: %s", obj_type_to_str(obj_type),
         obj_id_str);

  FpiByteWriter writer;
  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

  gboolean written = TRUE;
  fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_GET_OBJECT_DATA);
  fpi_byte_writer_put_uint32_le(&writer, obj_type);
  fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  CmdCallback callback;
  switch (obj_type)
  {
    case OBJ_TYPE_PAYLOADS: callback = recv_db2_get_payload_data; break;
    case OBJ_TYPE_TEMPLATES:
    case OBJ_TYPE_USERS:
    default: g_assert_not_reached();
  }

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      callback);
}

/* VCSFW_CMD_GET_OBJECT_DELETE_OBJECT ====================================== */

static void recv_db2_delete_object(FpDevice *device, guint8 *buffer_in,
                                   gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 delete object callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint16 num_deleted;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_deleted);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "DB2 delete object response too short"));
    return;
  }

  fp_dbg("Number of deleted objects: %d", num_deleted);

  fpi_ssm_next_state(self->task_ssm);
}

static void send_db2_delete_object(FpiDeviceSynaTlsMoc *self,
                                   const ObjType obj_type, const Db2Id obj_id)
{
  const guint send_size = 21;
  const guint expected_recv_size = 4;

  g_autofree gchar *obj_id_str = bin2hex(obj_id, DB2_ID_SIZE);
  fp_dbg("Deleting %s with id: %s", obj_type_to_str(obj_type), obj_id_str);

  FpiByteWriter writer;
  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);

  gboolean written = TRUE;
  fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_DELETE_OBJECT);
  fpi_byte_writer_put_uint32_le(&writer, obj_type);
  fpi_byte_writer_put_data(&writer, obj_id, DB2_ID_SIZE);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_db2_delete_object);
}

/* VCSFW_CMD_DB2_CLEANUP =================================================== */

static void recv_db2_cleanup(FpDevice *device, guchar *buffer_in,
                             gsize length_in, GError *error)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  if (error != NULL)
  {
    goto error;
  }
  g_assert(buffer_in != NULL);

  FpiByteReader reader;
  fpi_byte_reader_init(&reader, buffer_in, length_in);

  gboolean read_ok = TRUE;
  /* no need to read status again */
  read_ok &= fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN);
  guint16 num_erased_slots = 0;
  read_ok &= fpi_byte_reader_get_uint16_le(&reader, &num_erased_slots);
  guint32 new_partition_version = 0;
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &new_partition_version);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_READ(read_ok);

  fp_dbg("DB2 cleanup succeeded with:");
  fp_dbg("\tNumber of erased slots: %u", num_erased_slots);
  fp_dbg("\tNew partition version: %u", new_partition_version);

error:
  if (error != NULL)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
  }
  else
  {
    fpi_ssm_next_state(self->task_ssm);
  }
}

static void send_db2_cleanup(FpiDeviceSynaTlsMoc *self)
{
  const guint send_size = 2;
  const guint expected_resp_size = 8;

  guint8 send_data[send_size];
  send_data[0] = VCSFW_CMD_DB2_CLEANUP;
  send_data[1] = 1;

  synatlsmoc_exec_cmd(self, FALSE, TRUE, send_data, send_size,
                      expected_resp_size, recv_db2_cleanup);
}

/* VCSFW_CMD_DB2_FORMAT ==================================================== */

static void recv_db2_format(FpDevice *device, guint8 *buffer_in,
                            gsize length_in, GError *error)
{
  fp_dbg("Receive DB2 format callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;
  guint32 new_partition_version;

  fpi_byte_reader_init(&reader, buffer_in, length_in);
  /* no need to read status again and skip over unknown4 */
  read_ok &=
      fpi_byte_reader_skip(&reader, SENSOR_FW_REPLY_STATUS_HEADER_LEN + 4);
  read_ok &= fpi_byte_reader_get_uint32_le(&reader, &new_partition_version);

  if (!read_ok)
  {
    fpi_ssm_mark_failed(self->task_ssm,
                        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                                             "DB2 format response too short"));
    return;
  }

  fp_dbg("Format succeded with new partition version: %d",
         new_partition_version);

  fpi_ssm_next_state(self->task_ssm);
}

static void send_db2_format(FpiDeviceSynaTlsMoc *self)
{
  fp_dbg("DB2 format command");
  const guint send_size = 12;
  const guint expected_recv_size = 8;

  FpiByteWriter writer;
  gboolean written = TRUE;

  fpi_byte_writer_init_with_size(&writer, send_size, TRUE);
  written &= fpi_byte_writer_put_uint8(&writer, VCSFW_CMD_DB2_FORMAT);
  written &= fpi_byte_writer_put_uint8(&writer, 1);
  written &= fpi_byte_writer_fill(&writer, 0, 10);

  FAIL_TASK_SSM_AND_RETURN_IF_NOT_WRITTEN(written);
  FAIL_TASK_SSM_AND_RETURN_ON_WRONG_SEND_SIZE(writer, send_size);

  g_autofree guint8 *cmd = fpi_byte_writer_reset_and_get_data(&writer);

  synatlsmoc_exec_cmd(self, FALSE, TRUE, cmd, send_size, expected_recv_size,
                      recv_db2_format);
}

/* non-fill_bulk communication functions =================================== */

/* tls status ============================================================== */

static void synatlsmoc_tls_status_cb(FpiUsbTransfer *transfer, FpDevice *device,
                                     gpointer userdata, GError *error)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  g_return_if_fail(transfer->ssm);

  if (error)
  {
    fpi_ssm_mark_failed(transfer->ssm, error);
    return;
  }

  if (transfer->actual_length < 1)
  {
    fpi_ssm_mark_failed(transfer->ssm,
                        fpi_device_error_new(FP_DEVICE_ERROR_PROTO));
    return;
  }

  self->server_established = FP_READ_UINT8(transfer->buffer) != 0;
  fp_dbg("<- server TLS session status: %s",
         self->server_established ? "established" : "not established");

  fpi_ssm_next_state(transfer->ssm);
}

static void synatlsmoc_get_tls_status(FpiDeviceSynaTlsMoc *self, FpiSsm *ssm)
{
  FpDevice *device = FP_DEVICE(self);

  fp_dbg("-> server TLS session status?");

  FpiUsbTransfer *transfer = fpi_usb_transfer_new(device);
  fpi_usb_transfer_fill_control(
      transfer, G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
      G_USB_DEVICE_REQUEST_TYPE_VENDOR, G_USB_DEVICE_RECIPIENT_DEVICE,
      REQUEST_TLS_SESSION_STATUS, 0, 0, TLS_SESSION_STATUS_RESP_LEN);

  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit(transfer, SYNATLSMOC_USB_CONTROL_TIMEOUT,
                          fpi_device_get_cancellable(device),
                          synatlsmoc_tls_status_cb, NULL);
}

/* bootloader exit / enter ================================================= */

static void reset_usb_device_on_callback(FpiUsbTransfer *transfer,
                                         FpDevice *device, gpointer user_data,
                                         GError *error)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  if (error != NULL)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  g_usb_device_reset(fpi_device_get_usb_device(device), &error);
  if (error != NULL)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  /* do not go to next, as we need to verify we exited bootloader mode */
  fpi_ssm_jump_to_state(self->task_ssm, OPEN_GET_VERSION);
}

static void write_dft(FpiDeviceSynaTlsMoc *self, const guint8 *data,
                      const gsize data_size, FpiUsbTransferCallback callback)
{
  g_autofree char *data_str = bin2hex(data, data_size);
  fp_dbg("DFT -> %s", data_str);

  /* Send data */
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new(FP_DEVICE(self));
  fpi_usb_transfer_fill_control(transfer, G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                G_USB_DEVICE_RECIPIENT_DEVICE,
                                REQUEST_DFT_WRITE, 0, 0, data_size);

  transfer->short_is_error = FALSE;
  transfer->ssm = self->task_ssm;
  memcpy(transfer->buffer, data, data_size);

  fpi_usb_transfer_submit(transfer, SYNATLSMOC_USB_CONTROL_TIMEOUT, NULL,
                          callback, NULL);
}

/**
 * Sends a command to enter/exit bootloader mode
 *
 * @param enter TRUE to enter BL mode, FALSE to exit
 * NOTE: the enter bootloader part is mainly for testing of the exit part
 */
static void send_bootloader_mode_enter_exit(FpiDeviceSynaTlsMoc *self,
                                            BootloaderModeEnterExit type)
{
  const guint8 to_send_exit[8] = {0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00};
  const guint8 to_send_enter[8] = {0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x01, 0x00};
  const guint8 *to_send = NULL;

  switch (type)
  {
    case BOOTLOADER_MODE_EXIT:
      fp_dbg("Entering bootloader mode");
      to_send = to_send_enter;
      break;
    case BOOTLOADER_MODE_ENTER:
      fp_dbg("Exiting bootloader mode");
      to_send = to_send_exit;
      break;
    default:
      fp_err("Received undefined bootloader mode enter/exit type: %d", type);
      g_assert_not_reached();
      break;
  }

  write_dft(self, to_send, 8, reset_usb_device_on_callback);
}

/* end of communication function =========================================== */

static void synatlsmoc_load_sample_pairing_data(FpiDeviceSynaTlsMoc *self)
{
  GError *local_error = NULL;

  guint8 *privkey_pem;
  gsize privkey_pem_len;

  guint8 *client_cert_raw = sample_recv_host_cert;
  gsize client_cert_len = CERTIFICATE_SIZE;

  guint8 *server_cert_raw = sample_sensor_cert;
  gsize server_cert_len = CERTIFICATE_SIZE;

  privkey_pem = sample_privkey_pem;
  privkey_pem_len = sizeof(sample_privkey_pem);

#ifdef DEBUG
  g_autofree gchar *client_cert_str = bin2hex(client_cert_raw, client_cert_len);
  g_autofree gchar *server_cert_str = bin2hex(server_cert_raw, server_cert_len);
  fp_dbg("Loading sample pairing data:");
  fp_dbg("\thost cert: %s", client_cert_str);
  fp_dbg("\tsensor cert: %s", server_cert_str);
  fp_dbg("\tprivate key:\n\n%.*s", (int) privkey_pem_len, privkey_pem);
#endif

  g_autoptr(OSSL_DECODER_CTX) dctx = OSSL_DECODER_CTX_new_for_pkey(
      &self->pairing_data.client_key, "PEM", NULL, "EC",
      OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, NULL,
      NULL);

  if (dctx == NULL ||
      OSSL_DECODER_from_data(dctx, (const guint8 **) &privkey_pem,
                             &privkey_pem_len) <= 0)
    g_assert_not_reached();

  self->pairing_data.client_cert_raw =
      g_memdup2(client_cert_raw, client_cert_len);
  self->pairing_data.client_cert_len = client_cert_len;

  self->pairing_data.server_cert_raw =
      g_memdup2(server_cert_raw, server_cert_len);
  self->pairing_data.server_cert_len = server_cert_len;

  if (!sensor_certificate_from_raw(&self->pairing_data.client_cert,
                                   client_cert_raw, client_cert_len,
                                   &local_error))
  {
    fpi_ssm_mark_failed(self->task_ssm, set_and_report_error(
                                            FP_DEVICE_ERROR_PROTO,
                                            "Cannot parse host certificate: %s",
                                            local_error->message));
    g_error_free(local_error);
    return;
  }

  if (!sensor_certificate_from_raw(&self->pairing_data.server_cert,
                                   server_cert_raw, server_cert_len,
                                   &local_error))
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "Cannot parse sensor certificate: %s",
                             local_error->message));
    g_error_free(local_error);
    return;
  }
}

static void synatlsmoc_event_interrupt_cb(FpiUsbTransfer *transfer,
                                          FpDevice *device, gpointer user_data,
                                          GError *error)
{
  fp_dbg("Wait for events callback");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  if (error)
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  FpiByteReader reader;
  gboolean read_ok = TRUE;

  guint8 sensor_seq_num = 0;
  ;

  // Get current sequence number
  fpi_byte_reader_init(&reader, transfer->buffer, transfer->actual_length);
  read_ok &= fpi_byte_reader_skip(&reader, 6);
  read_ok &= fpi_byte_reader_get_uint8(&reader, &sensor_seq_num);

  if (!read_ok)
  {
    error =
        set_and_report_error(FP_DEVICE_ERROR_PROTO, "Interrupt data too short");
    fpi_ssm_mark_failed(transfer->ssm, error);
  }

  fp_dbg("Event sequence numbers: host=%d, sensor=%d", self->event_seq_num,
         sensor_seq_num);

  send_event_read(self);
}

static void synatlsmoc_wait_for_events(FpiDeviceSynaTlsMoc *self)
{
  fp_dbg("Waiting for events...");

  FpiUsbTransfer *transfer = fpi_usb_transfer_new(FP_DEVICE(self));
  transfer->ssm = self->task_ssm;
  transfer->short_is_error = TRUE;

  fpi_usb_transfer_fill_interrupt(transfer, SYNATLSMOC_EP_INTERRUPT, 7);
  fpi_usb_transfer_submit(transfer, SYNATLSMOC_USB_INTERRUPT_TIMEOUT,
                          self->interrupt_cancellable,
                          synatlsmoc_event_interrupt_cb, NULL);
}

static char *export_private_key_to_pem(EVP_PKEY *pkey, GError **error)
{
  BIO *bio = BIO_new(BIO_s_mem());  // Create a memory BIO
  if (bio == NULL)
  {
    *error =
        set_and_report_error(FP_DEVICE_ERROR_GENERAL, "Failed to create BIO");
    return NULL;
  }

  // Write the private key to the BIO in PEM format
  if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1)
  {
    *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                  "Failed to write private key to BIO");
    BIO_free(bio);
    return NULL;
  }

  // Get the length of the data in the BIO
  long pem_length = BIO_ctrl_pending(bio);
  if (pem_length <= 0)
  {
    *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL, "No data in BIO");
    BIO_free(bio);
    return NULL;
  }

  // Allocate memory for the PEM string
  char *pem_data = (char *) malloc(pem_length + 1);
  if (pem_data == NULL)
  {
    *error = set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                                  "Failed to allocate memory for PEM data");
    BIO_free(bio);
    return NULL;
  }

  // Read the data from the BIO into the string
  BIO_read(bio, pem_data, pem_length);
  pem_data[pem_length] = '\0';  // Null-terminate the string

  // Clean up
  BIO_free(bio);

  return pem_data;  // Return the PEM string
}

static void store_pairing_data(FpiDeviceSynaTlsMoc *self)
{
  // FIXME: raw cert lengths from pairing data and check on loading

  guint8 *client_cert_raw_cpy =
      g_memdup2(self->pairing_data.client_cert_raw, CERTIFICATE_SIZE);
  GVariant *client_cert_var = g_variant_new_fixed_array(
      G_VARIANT_TYPE_BYTE, client_cert_raw_cpy, CERTIFICATE_SIZE, 1);

  guint8 *server_cert_raw_cpy =
      g_memdup2(self->pairing_data.server_cert_raw, CERTIFICATE_SIZE);
  GVariant *server_cert_var = g_variant_new_fixed_array(
      G_VARIANT_TYPE_BYTE, server_cert_raw_cpy, CERTIFICATE_SIZE, 1);

  GError *local_error = NULL;
  char *privkey_pem =
      export_private_key_to_pem(self->pairing_data.client_key, &local_error);
  if (privkey_pem == NULL)
  {
    fpi_ssm_mark_failed(self->task_ssm, local_error);
    return;
  }

  GVariant *privkey_pem_var = g_variant_new_string(privkey_pem);

  GVariant *pairing_data = g_variant_new("(@ay@ay@s)", client_cert_var,
                                         server_cert_var, privkey_pem_var);

  g_object_set(FP_DEVICE(self), "fpi-persistent-data", pairing_data, NULL);

#ifdef DEBUG
  g_autofree char *client_cert_str =
      bin2hex(client_cert_raw_cpy, CERTIFICATE_SIZE);
  g_autofree char *server_cert_str =
      bin2hex(server_cert_raw_cpy, CERTIFICATE_SIZE);

  fp_dbg("Successfully stored pairing data:");
  fp_dbg("\tClient certificate: %s", client_cert_str);
  fp_dbg("\tServer certificate: %s", server_cert_str);
  fp_dbg("\tPEM private key:\n%s", privkey_pem);
#endif

  fpi_ssm_next_state(self->task_ssm);
}

static void load_pairing_data(FpiDeviceSynaTlsMoc *self)
{
  GError *local_error = NULL;

#ifdef DEBUG
  fp_dbg("Loading pairing data form persistent storage:");
#endif

  g_autoptr(GVariant) pairing_data = NULL;
  g_autoptr(GVariant) client_cert_var = NULL;
  g_autoptr(GVariant) server_cert_var = NULL;
  g_autoptr(GVariant) privkey_pem_var = NULL;

  g_object_get(FP_DEVICE(self), "fpi-persistent-data", &pairing_data, NULL);

  if (pairing_data == NULL)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                             "Received NULL as stored pairing data"));
    return;
  }

  if (!g_variant_check_format_string(pairing_data, "(@ay@ay@s)", FALSE))
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_GENERAL,
                             "Stored pairing data have incorrect format"));
    return;
  }

  g_variant_get(pairing_data, "(@ay@ay@s)", &client_cert_var, &server_cert_var,
                &privkey_pem_var);

  gsize client_cert_data_size = 0;
  guint8 *client_cert_data = (guint8 *) g_variant_get_fixed_array(
      client_cert_var, &client_cert_data_size, 1);
  if (client_cert_data_size != CERTIFICATE_SIZE)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(
            FP_DEVICE_ERROR_GENERAL,
            "Stored sensor/client certificate has invalid size: %lu",
            client_cert_data_size));
    return;
  }
  self->pairing_data.client_cert_raw =
      g_memdup2(client_cert_data, CERTIFICATE_SIZE);
  self->pairing_data.client_cert_len = CERTIFICATE_SIZE;

#ifdef DEBUG
  g_autofree char *client_cert_str =
      bin2hex(self->pairing_data.client_cert_raw, CERTIFICATE_SIZE);
  fp_dbg("\tClient certificate: %s", client_cert_str);
#endif

  gsize server_cert_data_size = 0;
  guint8 *server_cert_data = (guint8 *) g_variant_get_fixed_array(
      server_cert_var, &server_cert_data_size, 1);
  if (server_cert_data_size != CERTIFICATE_SIZE)
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(
            FP_DEVICE_ERROR_GENERAL,
            "Stored host/server certificate has invalid size: %lu",
            server_cert_data_size));
    return;
  }
  self->pairing_data.server_cert_raw =
      g_memdup2(server_cert_data, CERTIFICATE_SIZE);
  self->pairing_data.server_cert_len = CERTIFICATE_SIZE;

#ifdef DEBUG
  g_autofree char *server_cert_str =
      bin2hex(self->pairing_data.server_cert_raw, CERTIFICATE_SIZE);
  fp_dbg("\tServer certificate: %s", server_cert_str);
#endif

  gsize privkey_pem_size = 0;
  // fIXME: autofree
  const gchar *privkey_pem =
      g_variant_get_string(privkey_pem_var, &privkey_pem_size);

#ifdef DEBUG
  fp_dbg("\tPEM private key:\n%s", privkey_pem);
#endif

  g_autoptr(OSSL_DECODER_CTX) dctx = OSSL_DECODER_CTX_new_for_pkey(
      &self->pairing_data.client_key, "PEM", NULL, "EC",
      OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, NULL,
      NULL);

  if (dctx == NULL ||
      OSSL_DECODER_from_data(dctx, (const guint8 **) &privkey_pem,
                             &privkey_pem_size) <= 0)
    g_assert_not_reached();

  if (!sensor_certificate_from_raw(
          &self->pairing_data.client_cert, self->pairing_data.client_cert_raw,
          self->pairing_data.client_cert_len, &local_error))
  {
    fpi_ssm_mark_failed(self->task_ssm, set_and_report_error(
                                            FP_DEVICE_ERROR_PROTO,
                                            "Cannot parse host certificate: %s",
                                            local_error->message));
    g_error_free(local_error);
    return;
  }

  if (!sensor_certificate_from_raw(
          &self->pairing_data.server_cert, self->pairing_data.server_cert_raw,
          self->pairing_data.server_cert_len, &local_error))
  {
    fpi_ssm_mark_failed(
        self->task_ssm,
        set_and_report_error(FP_DEVICE_ERROR_PROTO,
                             "Cannot parse sensor certificate: %s",
                             local_error->message));
    g_error_free(local_error);
    return;
  }
}

static void pair(FpiDeviceSynaTlsMoc *self)
{
  if (!synatlsmoc_is_provisioned(self))
  {
    fp_warn("Skipping pairing: sensor is already paired or insecure");
    return;
  }

  if (!synatlsmoc_has_advanced_security(self))
  {
    fp_warn(
        "Skipping pairing: only advanced security is supported (per "
        "Windows driver)");
    fpi_ssm_next_state(self->task_ssm);
    return;
  }

  fp_dbg("Pairing sensor");

  self->pairing_data.client_key = EVP_EC_gen("prime256v1");

  /* we create it already serialized, as we do not need it in struct form */
  GError *error = NULL;
  g_autofree guint8 *host_certificate_raw = NULL;
  if (!create_host_certificate(self->pairing_data.client_key,
                               &host_certificate_raw, &error))
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  /* saves received certificates to self */
  send_pair(self, host_certificate_raw);
}

static void fetch_pairing_data(FpiDeviceSynaTlsMoc *self)
{
#ifdef USE_SAMPLE_PAIRING_DATA
  fp_warn(
      "Using sample pairing data, you should not see this during normal use");
  synatlsmoc_load_sample_pairing_data(self);
  /* skip over pairing states */
  fpi_ssm_jump_to_state(self->task_ssm, OPEN_VERIFY_SENSOR_CERTIFICATE);
#else
  g_autoptr(GVariant) pairing_data = NULL;
  g_object_get(FP_DEVICE(self), "fpi-persistent-data", &pairing_data, NULL);

  if ((!synatlsmoc_is_provisioned(self)) || pairing_data == NULL)
  {
    if (pairing_data == NULL)
      fp_warn("Pairing data in persistent storage are NULL");
    if (!synatlsmoc_is_provisioned(self)) fp_warn("Sensor is not provisioned");

    fp_warn("Need to pair sensor");
    fpi_ssm_next_state(self->task_ssm); /* OPEN_SEND_PAIR */
  }
  else
  {
    load_pairing_data(self);
    /* skip over pairing states */
    fpi_ssm_jump_to_state(self->task_ssm, OPEN_VERIFY_SENSOR_CERTIFICATE);
  }
#endif
}

static void synatlsmoc_open_done(FpiSsm *ssm, FpDevice *device, GError *error)
{
  if (error)
  {
    g_usb_device_release_interface(fpi_device_get_usb_device(device), 0, 0,
                                   NULL);
    synatlsmoc_task_ssm_done(ssm, device, error);
    return;
  }

  synatlsmoc_task_ssm_done(ssm, device, NULL);
  fpi_device_open_complete(device, NULL);
}

static void synatlsmoc_open_run_state(FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(dev);
  OpenData *open_ssm_data = fpi_ssm_get_data(ssm);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case OPEN_TLS_STATUS: synatlsmoc_get_tls_status(self, ssm); break;
    case OPEN_HANDLE_TLS_STATUSES:
      if ((self->session != NULL) && (!self->server_established))
      {
        fp_warn("Host is in TLS session but sensor is not");
        tls_session_free(self->session);
        self->session = NULL;
        fpi_ssm_jump_to_state(ssm, OPEN_GET_VERSION);
      }
      else if (self->session == NULL && self->server_established)
      {
        fp_warn("Sensor is in TLS session but host is not");
        fpi_ssm_next_state(ssm);
      }
      else if (self->session != NULL && self->server_established)
      {
        fp_dbg("Host and sensor are already in TLS session");
        fpi_ssm_mark_completed(ssm);
      }
      else
      {  // both not established
        fpi_ssm_jump_to_state(ssm, OPEN_GET_VERSION);
      }
      break;
    case OPEN_FORCE_TLS_CLOSE:
      g_assert(self->server_established);
      send_cmd_to_force_close_sensor_tls_session(self);
      break;
    case OPEN_GET_VERSION: send_get_version(self); break;
    case OPEN_EXIT_BOOTLOADER:
      if (synatlsmoc_is_in_bootloader_mode(self))
      {
        if (open_ssm_data->tried_to_exit_bootloader_mode)
        {
          fpi_ssm_mark_failed(ssm, set_and_report_error(
                                       FP_DEVICE_ERROR_NOT_SUPPORTED,
                                       "Sensor doesn't have a valid firmware, "
                                       "need to update to a valid one first!"));
        }
        else
        {
          open_ssm_data->tried_to_exit_bootloader_mode = TRUE;
          send_bootloader_mode_enter_exit(self, BOOTLOADER_MODE_EXIT);
        }
      }
      else
      {
        fpi_ssm_next_state(ssm);
      }
      break;
    case OPEN_LOAD_SENSOR_KEY: synatlsmoc_load_sensor_key(self); break;
    case OPEN_LOAD_PAIRING_DATA:
      if (synatlsmoc_is_provisioned(self) ||
          synatlsmoc_has_advanced_security(self))
      {
        fetch_pairing_data(self);
      }
      else
      {
        fpi_ssm_mark_failed(
            ssm, set_and_report_error(
                     FP_DEVICE_ERROR_NOT_SUPPORTED,
                     "Sensor is unprovisioned or does not support advanced "
                     "security, cannot establishing TLS session"));
      }
      break;
    case OPEN_SEND_PAIR:
    {
      pair(self);
      break;
    }
    case OPEN_SAVE_PAIRING_DATA:
    {
      store_pairing_data(self);
      break;
    }
    case OPEN_VERIFY_SENSOR_CERTIFICATE:
      synatlsmoc_verify_sensor_certificate(self);
      break;
    case OPEN_TLS_ESTABLISH:
    {
      self->session = tls_session_new();

      if (!tls_session_init(self->session, &self->pairing_data, &error))
      {
        fpi_ssm_mark_failed(ssm, error);
        break;
      }

      if (!tls_session_establish(self->session, &error))
      {
        fpi_ssm_mark_failed(ssm, error);
        break;
      }

      fpi_ssm_next_state(ssm);
      break;
    }
    case OPEN_TLS_SEND_DATA:
    {
      g_autofree guint8 *tls_data = NULL;
      gsize tls_data_len = 0;

      if (!tls_session_flush_send_buffer(self->session, &tls_data,
                                         &tls_data_len, &error))
      {
        fpi_ssm_mark_failed(ssm, error);
        break;
      }

      send_tls_data(self, tls_data, tls_data_len);
      break;
    }
    case OPEN_SET_EVENT_MASK:
    {
      send_event_config(self, NO_EVENTS);
      break;
    }
  }
}

static void synatlsmoc_open(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Open");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  GError *error = NULL;

  self->interrupt_cancellable = g_cancellable_new();

  if (!g_usb_device_reset(fpi_device_get_usb_device(device), &error))
  {
    fpi_device_open_complete(device, error);
    return;
  }

  if (!g_usb_device_claim_interface(fpi_device_get_usb_device(device), 0, 0,
                                    &error))
  {
    fpi_device_open_complete(device, error);
    return;
  }

  self->task_ssm = fpi_ssm_new_full(device, synatlsmoc_open_run_state,
                                    OPEN_NUM_STATES, OPEN_NUM_STATES, "Open");
  OpenData *open_ssm_data = g_new0(OpenData, 1);
  fpi_ssm_set_data(self->task_ssm, open_ssm_data, (GDestroyNotify) g_free);
  fpi_ssm_start(self->task_ssm, synatlsmoc_open_done);
  return;
}

static void synatlsmoc_cancel(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Cancel");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  g_cancellable_cancel(self->interrupt_cancellable);
  g_clear_object(&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new();
}

static void synatlsmoc_suspend(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Suspend");

  synatlsmoc_cancel(device);
  g_cancellable_cancel(fpi_device_get_cancellable(device));
  fpi_device_suspend_complete(device, NULL);
}

static void synatlsmoc_close_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(dev);

  tls_session_free(self->session);
  self->session = NULL;

  // FIXME: causes errors
  // free_pairing_data(&self->pairing_data);

  g_usb_device_release_interface(fpi_device_get_usb_device(dev), 0, 0, &error);

  synatlsmoc_task_ssm_done(ssm, dev, error);

  if (!error) fpi_device_close_complete(dev, NULL);
}

static void close_tls_session(FpiDeviceSynaTlsMoc *self)
{
  GError *error = NULL;
  g_autofree guint8 *tls_data = NULL;

  fp_dbg("Closing TLS session...");
  if (!tls_session_close(self->session, &error))
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  gsize tls_size;

  if (!tls_session_flush_send_buffer(self->session, &tls_data, &tls_size,
                                     &error))
  {
    fpi_ssm_mark_failed(self->task_ssm, error);
    return;
  }

  // FIXME: callback was made for open only (why was this here if it works?)
  synatlsmoc_exec_cmd(self, TRUE, FALSE, tls_data, tls_size, 256,
                      recv_tls_data);
}

static void synatlsmoc_close_ssm_run_state(FpiSsm *ssm, FpDevice *dev)
{
  GError *error = NULL;
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(dev);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case CLOSE_EVENT_MASK_NONE:
      send_event_config(self, NO_EVENTS);
      if (error) fpi_ssm_mark_failed(ssm, error);
      break;
    case CLOSE_TLS_SESSION_CLOSE:
      if (self->session)
      {
        close_tls_session(self);
      }
      break;
  }
}

static void synatlsmoc_close(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Close");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  g_cancellable_cancel(self->interrupt_cancellable);
  g_clear_object(&self->interrupt_cancellable);

  self->task_ssm =
      fpi_ssm_new_full(device, synatlsmoc_close_ssm_run_state, CLOSE_NUM_STATES,
                       CLOSE_NUM_STATES, "Close");
  fpi_ssm_start(self->task_ssm, synatlsmoc_close_ssm_done);
}

static void list_data_free(ListData *data)
{
  g_clear_pointer(&data->list_result, g_ptr_array_unref);
  g_free(data);
}

static void synatlsmoc_list_run_state(FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  ListData *data = fpi_ssm_get_data(ssm);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case LIST_DB2_GET_DB_INFO:
    {
      // get number of current db2 objects
      send_db2_info(self);
      break;
    }
    case LIST_DB2_CLEANUP:
    {
      if (data->cleanup_required)
      {
        send_db2_cleanup(self);
      }
      else
      {
        fpi_ssm_next_state(ssm);
      }
      break;
    }

    case LIST_DB2_GET_TEMPLATES_LIST:
    {
      data->list_template_id = g_ptr_array_new_with_free_func(g_free);
      send_db2_get_object_list(self, OBJ_TYPE_TEMPLATES, cache_tuid);
      break;
    }
    case LIST_DB2_GET_PAYLOAD_LIST:
    {
      if (data->list_payload_id) g_ptr_array_free(data->list_payload_id, TRUE);
      data->list_payload_id = g_ptr_array_new_with_free_func(g_free);

      if (data->current_template_id) g_free(data->current_template_id);
      data->current_template_id =
          g_ptr_array_steal_index(data->list_template_id, 0);

      send_db2_get_object_list(self, OBJ_TYPE_PAYLOADS,
                               *data->current_template_id);
      break;
    }
    case LIST_DB2_GET_PAYLOAD_INFO:
    {
      if (data->current_payload_id) g_free(data->current_payload_id);
      data->current_payload_id =
          g_ptr_array_steal_index(data->list_payload_id, 0);

      send_db2_get_object_info(self, OBJ_TYPE_PAYLOADS,
                               *data->current_payload_id);
      break;
    }
    case LIST_DB2_GET_PAYLOAD_DATA:
    {
      send_db2_get_object_data(self, OBJ_TYPE_PAYLOADS,
                               *data->current_payload_id,
                               data->current_payload_size);
      break;
    }
    case LIST_REPORT:
    {
      g_ptr_array_free(data->list_template_id, TRUE);

      if (data->list_payload_id) g_ptr_array_free(data->list_payload_id, TRUE);

      if (data->current_template_id) g_free(data->current_template_id);
      if (data->current_payload_id) g_free(data->current_payload_id);

      fpi_device_list_complete(device, g_steal_pointer(&data->list_result),
                               NULL);
      fpi_ssm_next_state(ssm);
      break;
    }
  }
}

static void synatlsmoc_list(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("List");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  ListData *data = g_new0(ListData, 1);

  data->list_result = g_ptr_array_new_with_free_func(g_object_unref);

  g_assert(self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new_full(device, synatlsmoc_list_run_state,
                                    LIST_NUM_STATES, LIST_NUM_STATES, "List");
  fpi_ssm_set_data(self->task_ssm, data, (GDestroyNotify) list_data_free);
  fpi_ssm_start(self->task_ssm, synatlsmoc_task_ssm_done);
}

static void synatlsmoc_delete_ssm_done(FpiSsm *ssm, FpDevice *dev,
                                       GError *error)
{
  synatlsmoc_task_ssm_done(ssm, dev, error);

  if (!error) fpi_device_delete_complete(dev, NULL);
}

static gboolean get_template_id_from_fp_print(FpPrint *print, Db2Id template_id,
                                              GError **error)
{
  gboolean ret = TRUE;

  g_autoptr(GVariant) fpi_data = NULL;
  g_autoptr(GVariant) user_id_var = NULL;
  g_autoptr(GVariant) tid_var = NULL;
  const guint8 *tid = NULL;

  g_return_val_if_fail(print != NULL, FALSE);

  g_object_get(print, "fpi-data", &fpi_data, NULL);

  if (!g_variant_check_format_string(fpi_data, "(y@ay@ay)", FALSE))
  {
    *error = set_and_report_error(FP_DEVICE_ERROR_DATA_INVALID,
                                  "Print data has invalid fpi-data format");
    ret = FALSE;
    goto error;
  }

  guint8 finger_id = 0;
  g_variant_get(fpi_data, "(y@ay@ay)", finger_id, &tid_var, &user_id_var);

  gsize tid_len = 0;
  tid = g_variant_get_fixed_array(tid_var, &tid_len, 1);
  if (tid_len != DB2_ID_SIZE)
  {
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

static void synatlsmoc_delete_run_state(FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(dev);
  DeleteData *delete_ssm_data = fpi_ssm_get_data(ssm);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case DELETE_GET_USER_ID:
    {
      send_db2_get_object_info(self, OBJ_TYPE_TEMPLATES,
                               delete_ssm_data->template_id);
      break;
    }
    case DELETE_DELETE_TEMPLATE:
    {
      send_db2_delete_object(self, OBJ_TYPE_TEMPLATES,
                             delete_ssm_data->template_id);
      break;
    }
    case DELETE_DELETE_USER:
    {
      send_db2_delete_object(self, OBJ_TYPE_USERS, delete_ssm_data->user_id);
      break;
    }
  }
}

static void synatlsmoc_delete(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Delete");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  FpPrint *print_to_delete = NULL;

  DeleteData *delete_ssm_data = g_new0(DeleteData, 1);

  fpi_device_get_delete_data(device, &print_to_delete);

  GError *error = NULL;
  if (!get_template_id_from_fp_print(print_to_delete,
                                     delete_ssm_data->template_id, &error))
  {
    fpi_device_delete_complete(device, error);
    return;
  }

  g_assert(self->task_ssm == NULL);
  self->task_ssm =
      fpi_ssm_new_full(device, synatlsmoc_delete_run_state, DELETE_NUM_STATES,
                       DELETE_NUM_STATES, "Delete");
  fpi_ssm_set_data(self->task_ssm, delete_ssm_data, g_free);
  fpi_ssm_start(self->task_ssm, synatlsmoc_delete_ssm_done);
}

static void enroll_data_free(EnrollData *data)
{
  g_free(data->template_id);
  g_free(data->user_id);
  g_free(data);
}

static void sensor_add_enrollment(FpiDeviceSynaTlsMoc *self, Db2Id *template_id,
                                  guint8 *user_id, guint8 finger_id)
{
  g_autoptr(TagVal) tagval = tagval_new();
  g_autofree guint8 *container = NULL;
  gsize container_size;

  tagval_add(tagval, ENROLL_TAG_TEMPLATE_ID, (guint8 *) template_id,
             DB2_ID_SIZE);
  tagval_add(tagval, ENROLL_TAG_USER_ID, user_id, WINBIO_SID_SIZE);
  tagval_add(tagval, ENROLL_TAG_FINGER_ID, &finger_id, 1);

  tagval_to_bytes(tagval, &container, &container_size);

  send_enroll_commit(self, container, container_size);
}

static void synatlsmoc_enroll_run_state(FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  EnrollData *data = fpi_ssm_get_data(ssm);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case ENROLL_ENROLL_START:
    {
      fp_dbg("Starting enroll process...");
      fp_dbg("\tuser_id: %s", data->user_id);
      fp_dbg("\tfinger_id: %d", data->finger_id);

      send_enroll_start(self);
      break;
    }
    case ENROLL_SET_EVENT_FINGER_UP:
      send_event_config(self, EV_FINGER_UP);
      break;
    case ENROLL_WAIT_FINGER_UP: synatlsmoc_wait_for_events(self); break;
    case ENROLL_SET_EVENT_FRAME_READY:
      send_event_config(self, EV_FRAME_READY);
      break;
    case ENROLL_SEND_FRAME_ACQUIRE:
      data->frame_acquire_retry_idx = FRAME_ACQUIRE_NUM_RETRIES;
      send_frame_acquire(self, CAPTURE_FLAG_ENROLL);
      break;
    case ENROLL_SET_EVENT_FINGER_DOWN:
      send_event_config(self, EV_FINGER_DOWN | EV_FRAME_READY);
      break;
    case ENROLL_WAIT_FINGER_DOWN:
      fpi_device_report_finger_status(device, FP_FINGER_STATUS_NEEDED);
      synatlsmoc_wait_for_events(self);
      break;
    case ENROLL_SET_EVENT_NONE:
      fpi_device_report_finger_status(device, FP_FINGER_STATUS_PRESENT);
      send_event_config(self, NO_EVENTS);
      break;
    case ENROLL_SEND_FRAME_FINISH: sensor_frame_finish(self); break;
    case ENROLL_SEND_ADD_IMAGE: send_add_image(self); break;
    case ENROLL_ADD_ENROLLMENT:
      sensor_add_enrollment(self, data->template_id, data->user_id,
                            data->finger_id);
      break;
    case ENROLL_ENROLL_FINISH: send_enroll_finish(self); break;
    case ENROLL_REPORT:
    {
      synatlsmoc_set_print_data(data->print, data->template_id, data->user_id,
                                data->finger_id);

      fpi_device_enroll_complete(device, g_object_ref(data->print), NULL);

      fpi_ssm_next_state(ssm);
      break;
    }
  }
}

static void synatlsmoc_enroll(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Enroll");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);
  EnrollData *data = g_new0(EnrollData, 1);

  fpi_device_get_enroll_data(device, &data->print);

  gchar *user_id = fpi_print_generate_user_id(data->print);
  data->user_id = (guint8 *) g_strndup(user_id, WINBIO_SID_SIZE);

  data->finger_id = fp_print_get_finger(data->print);

  g_assert(self->task_ssm == NULL);
  self->task_ssm =
      fpi_ssm_new_full(device, synatlsmoc_enroll_run_state, ENROLL_NUM_STATES,
                       ENROLL_NUM_STATES, "Enroll");
  fpi_ssm_set_data(self->task_ssm, data, (GDestroyNotify) enroll_data_free);
  fpi_ssm_start(self->task_ssm, synatlsmoc_task_ssm_done);
}
static void synatlsmoc_identify_verify_run_state(FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case IDENTIFY_VERIFY_SET_EVENT_FRAME_READY:
      fp_dbg("Capturing image...");
      send_event_config(self, EV_FRAME_READY);
      break;
    case IDENTIFY_VERIFY_SEND_FRAME_ACQUIRE:;
      VerifyIdentifyData *ssm_data = fpi_ssm_get_data(ssm);
      ssm_data->frame_acquire_retry_idx = FRAME_ACQUIRE_NUM_RETRIES;
      send_frame_acquire(self, CAPTURE_FLAG_AUTH);
      break;
    case IDENTIFY_VERIFY_SET_EVENT_FINGER_DOWN:
      send_event_config(self, EV_FINGER_DOWN | EV_FRAME_READY);
      break;
    case IDENTIFY_VERIFY_WAIT_FINGER_DOWN:
      fpi_device_report_finger_status(device, FP_FINGER_STATUS_NEEDED);
      synatlsmoc_wait_for_events(self);
      break;
    case IDENTIFY_VERIFY_SET_EVENT_NONE:
      fpi_device_report_finger_status(device, FP_FINGER_STATUS_PRESENT);
      send_event_config(self, NO_EVENTS);
      break;
    case IDENTIFY_VERIFY_SEND_FRAME_FINISH: sensor_frame_finish(self); break;
    case IDENTIFY_VERIFY_IMAGE_METRICS:
      send_get_image_metrics(self, MIS_IMAGE_METRICS_IMG_QUALITY);
      break;
    case IDENTIFY_VERIFY_IDENTIFY_MATCH:
      if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_IDENTIFY)
      {
        send_identify_match(self, NULL, 0);
      }
      else
      {
        FpPrint *print_to_verify = NULL;
        Db2Id verify_template_id;

        fpi_device_get_verify_data(device, &print_to_verify);

        GError *error = NULL;
        if (!get_template_id_from_fp_print(print_to_verify, verify_template_id,
                                           &error))
        {
          fpi_ssm_mark_failed(ssm, error);
          break;
        }
        send_identify_match(self, &verify_template_id, 1);
      }
      break;
    case IDENTIFY_VERIFY_COMPLETE:
      if (fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_IDENTIFY)
        fpi_device_identify_complete(device, NULL);
      else
        fpi_device_verify_complete(device, NULL);
      fpi_ssm_next_state(ssm);
      break;
  }
}

static void synatlsmoc_identify_verify(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Identify or Verify");
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  g_assert(self->task_ssm == NULL);

  VerifyIdentifyData *ssm_data = g_new0(VerifyIdentifyData, 1);
  self->task_ssm = fpi_ssm_new_full(
      device, synatlsmoc_identify_verify_run_state, IDENTIFY_VERIFY_NUM_STATES,
      IDENTIFY_VERIFY_NUM_STATES, "Identify/Verify");
  fpi_ssm_set_data(self->task_ssm, ssm_data, g_free);
  fpi_ssm_start(self->task_ssm, synatlsmoc_task_ssm_done);
}

static void synatlsmoc_clear_storage_run_state(FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  switch (fpi_ssm_get_cur_state(ssm))
  {
    case CLEAR_STORAGE_DB2_FORMAT: send_db2_format(self); break;
    case IDENTIFY_VERIFY_COMPLETE:
      fpi_device_clear_storage_complete(device, NULL);
      fpi_ssm_next_state(ssm);
      break;
  }
}

static void synatlsmoc_clear_storage(FpDevice *device)
{
  FP_DBG_HIGHLIGHTED("Clear storage");

  FpiDeviceSynaTlsMoc *self = FPI_DEVICE_SYNATLSMOC(device);

  g_assert(self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new_full(device, synatlsmoc_clear_storage_run_state,
                                    CLEAR_STORAGE_NUM_STATES,
                                    CLEAR_STORAGE_NUM_STATES, "Clear storage");
  fpi_ssm_start(self->task_ssm, synatlsmoc_task_ssm_done);
}

static void fpi_device_synatlsmoc_init(FpiDeviceSynaTlsMoc *self)
{
  G_DEBUG_HERE();
}

static void fpi_device_synatlsmoc_class_init(FpiDeviceSynaTlsMocClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = SYNATLSMOC_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = SYNATLSMOC_ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  dev_class->temp_hot_seconds = -1;
  // FIXME: was this left out intentionally
  dev_class->temp_cold_seconds = -1;

  dev_class->open = synatlsmoc_open;
  dev_class->close = synatlsmoc_close;
  dev_class->enroll = synatlsmoc_enroll;
  dev_class->verify = synatlsmoc_identify_verify;
  dev_class->identify = synatlsmoc_identify_verify;
  dev_class->list = synatlsmoc_list;
  dev_class->delete = synatlsmoc_delete;
  dev_class->clear_storage = synatlsmoc_clear_storage;
  dev_class->cancel = synatlsmoc_cancel;
  dev_class->suspend = synatlsmoc_suspend;

  fpi_device_class_auto_initialize_features(dev_class);
}
