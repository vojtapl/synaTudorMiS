/*
 * TODO: add header
 */

#include "drivers_api.h"
#include "synaptics.h"
#include "states.h"
#include <glib.h>

#define USB_TIMEOUT_MS 2000

static const FpIdEntry id_table[] = {
   // only 00FF is tested
   // { .vid = 0x06CB,  .pid = 0x00C9, },
   // { .vid = 0x06CB,  .pid = 0x00D1, },
   // { .vid = 0x06CB,  .pid = 0x00E7, },
   { .vid = 0x06CB,  .pid = 0x00FF, },
   // { .vid = 0x06CB,  .pid = 0x0124, },
   // { .vid = 0x06CB,  .pid = 0x0169, },
  { .vid = 0,  .pid = 0,  .driver_data = 0 },   /* terminating entry */
};

// open -----------------------------------------------------------------------

static void
fp_init_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);

   switch (fpi_ssm_get_cur_state(self->task_ssm))
   {
      case INIT_SEND_GET_VERSION:
         break;
      case INIT_GET_BOOTLOADER_STATE:
         break;
   }
}

static void
fp_init_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("Init complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_open_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_open (FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
   GError *error = NULL;

   G_DEBUG_HERE ();

   /* Claim usb interface */
   if (!g_usb_device_claim_interface(fpi_device_get_usb_device (device), 0, 0, &error))
   {
      goto error;
   }

   g_assert(!self->task_ssm);

   self->task_ssm = fpi_ssm_new(device,
                           fp_init_ssm_run_state,
                           INIT_NUM_STATES);
   fpi_ssm_start (self->task_ssm, fp_init_ssm_done);

   return;

error:
   fpi_device_open_complete(FP_DEVICE (self), error);
}

// close ----------------------------------------------------------------------

static void
fp_close_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_close_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("close complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_close_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_close (FpDevice *device)
{
   // close the device again
}

// enroll ---------------------------------------------------------------------

static void
fp_enroll_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_enroll_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("enroll complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_enroll_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_enroll (FpDevice *device)
{
}

// verify ---------------------------------------------------------------------

static void
fp_verify_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_verify_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("verify complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_verify_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_verify (FpDevice *device)
{
   // starts a verify operation
}

// identify -------------------------------------------------------------------

static void
fp_identify_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_identify_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("identify complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_identify_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_identify (FpDevice *device)
{
   // starts an identify operation
}

// capture --------------------------------------------------------------------

static void
fp_capture_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_capture_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("capture complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_capture_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_capture (FpDevice *device)
{
}

// list -----------------------------------------------------------------------

static void
fp_list_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_list_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("list complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_list_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_list (FpDevice *device)
{
   // lists fingerprints
}

// delete_print ---------------------------------------------------------------

static void
fp_delete_print_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_delete_print_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("delete_print complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_delete_print_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_delete_print (FpDevice *device)
{
   // delete fingerprint
}

// clear_storage --------------------------------------------------------------

static void
fp_clear_storage_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_clear_storage_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("clear_storage complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_clear_storage_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_clear_storage (FpDevice *device)
{
   // delete all fingerprints
}

// cancel ---------------------------------------------------------------------

static void
fp_cancel_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (device);
}

static void
fp_cancel_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC (dev);
   fp_info("cancel complete!");
   if (fpi_ssm_get_error (self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_cancel_complete(dev, error);
   self->task_ssm = NULL;
}

static void
synaptics_moc_cancel (FpDevice *device)
{}

// suspend --------------------------------------------------------------------

static void
synaptics_moc_suspend (FpDevice *device)
{}

// resume ---------------------------------------------------------------------

static void
synaptics_moc_resume (FpDevice *device)
{}

// ----------------------------------------------------------------------------

static void
fpi_device_synaptics_moc_class_init (FpiDeviceSynapticsMocClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_ID;
  dev_class->full_name = SYNAPTICS_MOC_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  // TODO: features
  dev_class->nr_enroll_stages = SYNAPTICS_MOC_DRIVER_NR_ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  // TODO: set these numbers correctly
  dev_class->temp_hot_seconds = -1;
  dev_class->temp_cold_seconds = -1;

  // dev_class->usb_discover = synaptics_moc_usb_discover;
  // dev_class->probe = synaptics_moc_probe;
  dev_class->open = synaptics_moc_open;
  dev_class->close = synaptics_moc_close;
  dev_class->enroll = synaptics_moc_enroll;
  dev_class->verify = synaptics_moc_verify;
  dev_class->identify = synaptics_moc_identify;
  dev_class->capture = synaptics_moc_capture;
  dev_class->list = synaptics_moc_list;
  dev_class->delete = synaptics_moc_delete_print;
  dev_class->clear_storage = synaptics_moc_clear_storage;
  dev_class->cancel = synaptics_moc_cancel;
  dev_class->suspend = synaptics_moc_suspend;
  dev_class->resume = synaptics_moc_resume;

  fpi_device_class_auto_initialize_features (dev_class);
}

