/*
 * TODO: add header
 */

#include "communication.c"
#include "communication.h"
#include "device.h"
#include "drivers_api.h"
#include "synaptics_moc.h"
#include "tls.c"
#include "tls.h"

G_DEFINE_TYPE(FpiDeviceSynapticsMoc, fpi_device_synaptics_moc, FP_TYPE_DEVICE)

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

// open -----------------------------------------------------------------------

static void fp_init_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);

   switch (fpi_ssm_get_cur_state(self->task_ssm)) {
      // case INIT_SEND_GET_VERSION:
      //    break;
      // case INIT_GET_BOOTLOADER_STATE:
      //    break;
   }
}

static void fp_init_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("Init complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_open_complete(dev, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_open(FpDevice *device)
{
   fp_dbg("--- open start ---");
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
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
   // send_test(self, error);

   gboolean in_bootloader_mode =
       version_data.product_id == 'B' || version_data.product_id == 'C';
   g_assert(!in_bootloader_mode);

   guint8 provision_state = version_data.provision_state & 0xF;
   gboolean is_provisioned = provision_state == PROVISION_STATE_PROVISIONED;
   if (is_provisioned) {
      if (!self->pairing_data.present) {
         fp_err("No present pairing_data - need to pair / read from storage!");
         g_critical("\t-> Not implemented");
         g_assert(FALSE);
      }

      // TODO: verify sensor certificate
   }

   g_assert(!self->task_ssm);

   establish_tls_session(self, error);

   // self->task_ssm = fpi_ssm_new(device, fp_init_ssm_run_state,
   // INIT_NUM_STATES); fpi_ssm_start(self->task_ssm, fp_init_ssm_done);
   return;

error:
   fpi_device_open_complete(FP_DEVICE(self), error);
}

// close ----------------------------------------------------------------------

static void fp_close_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_close_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("close complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_close_complete(dev, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_close(FpDevice *device)
{
   fp_dbg("--- close start ---");
}

// enroll ---------------------------------------------------------------------

static void fp_enroll_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_enroll_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("enroll complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   // TODO:
   gpointer print = NULL;
   fpi_device_enroll_complete(dev, print, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_enroll(FpDevice *device)
{

   fp_dbg("--- enroll start ---");
}

// verify ---------------------------------------------------------------------

static void fp_verify_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_verify_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("verify complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_verify_complete(dev, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_verify(FpDevice *device)
{
   fp_dbg("--- verify start ---");
}

// identify -------------------------------------------------------------------

static void fp_identify_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_identify_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("identify complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_identify_complete(dev, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_identify(FpDevice *device)
{

   fp_dbg("--- identify start ---");
}

// capture --------------------------------------------------------------------

static void fp_capture_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_capture_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   fp_dbg("--- capture start ---");

   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("capture complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   // TODO:
   gpointer image = NULL;
   fpi_device_capture_complete(dev, image, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_capture(FpDevice *device) {}

// list -----------------------------------------------------------------------

static void fp_list_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_list_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("list complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   gpointer list = NULL;
   fpi_device_list_complete(dev, list, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_list(FpDevice *device)
{
   fp_dbg("--- list start ---");
}

// delete_print ---------------------------------------------------------------

static void fp_delete_print_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_delete_print_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("delete_print complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_delete_complete(dev, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_delete_print(FpDevice *device)
{
   fp_dbg("--- delete start ---");
}

// clear_storage --------------------------------------------------------------

static void fp_clear_storage_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_clear_storage_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("clear_storage complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   fpi_device_clear_storage_complete(dev, error);
   self->task_ssm = NULL;
}

static void synaptics_moc_clear_storage(FpDevice *device)
{
   fp_dbg("--- clear_storage start ---");
}

// cancel ---------------------------------------------------------------------

static void fp_cancel_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(device);
}

static void fp_cancel_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{
   FpiDeviceSynapticsMoc *self = FPI_DEVICE_SYNAPTICS_MOC(dev);
   fp_info("cancel complete!");
   if (fpi_ssm_get_error(self->task_ssm)) {
      error = fpi_ssm_get_error(self->task_ssm);
   }
   self->task_ssm = NULL;
}

static void synaptics_moc_cancel(FpDevice *device)
{
   fp_dbg("--- cancel start ---");
}

// suspend --------------------------------------------------------------------

static void synaptics_moc_suspend(FpDevice *device)
{
   fp_dbg("--- suspend start ---");
}

// resume ---------------------------------------------------------------------

static void synaptics_moc_resume(FpDevice *device)
{
   fp_dbg("--- resume start ---");
}

// ----------------------------------------------------------------------------

static void fpi_device_synaptics_moc_init(FpiDeviceSynapticsMoc *self)
{
   fp_dbg("--- init start ---");
}

static void
fpi_device_synaptics_moc_class_init(FpiDeviceSynapticsMocClass *klass)
{
   FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

   dev_class->id = FP_COMPONENT;
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

   fpi_device_class_auto_initialize_features(dev_class);
}
