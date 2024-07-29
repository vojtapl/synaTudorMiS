/*
 * TODO: add header
 */

#include <glib.h>
#include "commands.h"
#include "states.h"
#include "synaptics.h"

/*
 * TODO: add all communication things here
 * */

static void
fp_comm_ssm_run_state(FpiSsm *ssm, FpDevice *device)
{
   switch (fpi_ssm_get_cur_state(ssm))
   {
      case COMM_STATE_SEND:
         g_debug("Sending command: 0x%2x", cmd_id);
         break;
      case COMM_STATE_RECV:
         g_debug("Received response for command: 0x%2x", cmd_id);
         break;
   }

}

static void
fp_comm_ssm_done(FpiSsm *ssm, FpDevice *dev, GError *error)
{

}

static void
synaptics_secure_connect (FpiDeviceSynapticsMoc *self,
                          guint8 cmd_id,
                          guint8 trans_len,
                          guint8* trans_data,
                          guint8 recv_len,
                          guint8* recv_data)
{

   // setup SSM for communication
   g_assert(self->cmd_ssm == NULL);
   self->cmd_ssm = fpi_ssm_new(FP_DEVICE (self), fp_comm_ssm_run_state, COMM_NUM_STATES);

   // setup usb transfer
   g_autoptr(FpiUsbTransfer) transfer = NULL;
   transfer = fpi_usb_transfer_new(FP_DEVICE(self));
   fpi_usb_transfer_fill_bulk (transfer, EP_OUT, trans_len+1);


   /*
    * TODO: somehow send and receive a command
    */

   fpi_ssm_start(self->cmd_ssm, fp_comm_ssm_done);
}
