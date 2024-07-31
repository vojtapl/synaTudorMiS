#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include <glib.h>
#include <stdint.h>

G_DECLARE_FINAL_TYPE(FpiDeviceSynapticsMoc, fpi_device_synaptics_moc, FPI,
                     DEVICE_SYNAPTICS_MOC, FpDevice)

typedef struct {
   guint16 status;
   guint32 payload_len;
   guint8 *payload;
} msg_resp_t;

typedef struct {
   guint32 payload_len;
   guint8 *payload;
} msg_send_t;

typedef void (*CmdMsgCallback)(FpiDeviceSynapticsMoc *self, msg_resp_t *resp,
                               GError *error);

typedef struct {
   msg_send_t send;
   msg_resp_t resp;
} transmission_ssm_data;

struct _FpiDeviceSynapticsMoc {
   FpDevice parent;

   // TODO: not aplicable?
   // guint8                cmd_seq_num;
   // guint8                last_seq_num;

   FpiSsm *task_ssm;
   FpiSsm *cmd_ssm;
   transmission_ssm_data cmd_ssm_data;

   FpiUsbTransfer *cmd_pending_transfer;
   gboolean cmd_complete_on_removal;
   gboolean cmd_suspended;
   guint8 id_idx;

   // bmkt_sensor_version_t mis_version;

   gboolean action_starting;
   GCancellable *interrupt_cancellable;

   gint enroll_stage;
   gboolean finger_on_sensor;
   GPtrArray *list_result;

   // struct syna_enroll_resp_data enroll_resp_data;
   // syna_state_t state;
   // GError *delay_error;
};
