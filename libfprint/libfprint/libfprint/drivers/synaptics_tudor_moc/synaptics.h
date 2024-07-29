/*
 * TODO: add header
 */

#pragma once


#include "drivers/synaptics/synaptics.h"
#define IMAGE_QUALITY_THRESHOLD 50

#define MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE 0x1
#define MIS_IMAGE_METRICS_IMG_QUALITY 0x10000

#define VCSFW_STORAGE_TUDOR_PART_ID_SSFS 1
#define VCSFW_STORAGE_TUDOR_PART_ID_HOST 2

#define OBJ_TYPE_USERS 1
#define OBJ_TYPE_TEMPLATES 2
#define OBJ_TYPE_PAYLOADS 3

#define CONT_TAG_PROPERTY_ID 4
#define CONT_TAG_PROPERTY_DATA 5

#define HOST_TAG_VERSION 1
#define HOST_TAG_PAIRED_DATA 2

#define PAIR_DATA_TAG_VERSION 0
#define PAIR_DATA_TAG_HOST_CERT 1
#define PAIR_DATA_TAG_PRIVATE_KEY 2
#define PAIR_DATA_TAG_SENSOR_CERT 3
#define PAIR_DATA_TAG_PUB_KEY_SEC_DATA 4
#define PAIR_DATA_TAG_SSI_STORAGE_PSK_ID 5

#define ENROLL_TAG_TUID 0
#define ENROLL_TAG_USERID 1
#define ENROLL_TAG_SUBID 2

#define EV_FINGER_DOWN 1
#define EV_FINGER_UP 2
#define EV_FRAME_READY 24

#define STATUS_SMT_LIKE_PROCESSING 0x6EA

#define RESPONSE_OK_1 0x000
#define VCS_RESULT_SENSOR_BAD_CMD 0x401
#define VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_1 0x403
#define VCS_RESULT_GEN_OPERATION_DENIED 0x404
#define RESPONSE_BAD_PARAM_1 0x405
#define RESPONSE_BAD_PARAM_2 0x406
#define RESPONSE_BAD_PARAM_3 0x407
#define RESPONSE_OK_2 0x412
#define VCS_RESULT_MATCHER_MATCH_FAILED 0x509
#define VCS_RESULT_SENSOR_FRAME_NOT_READY 0x5B6
#define RESPONSE_OK_3 0x5CC
#define VCS_RESULT_DB_FULL 0x680
#define VCS_RESULT_GEN_OBJECT_DOESNT_EXIST_2 0x683
#define RESPONSE_PROCESSING_FRAME 0x6EA


#define FP_ID "synaptics_tudor_moc"
#define SYNAPTICS_MOC_DRIVER_FULLNAME "Synaptics Tudor Match-In-Sensor"

// TODO: is this constant and if not how to find the number
#define SYNAPTICS_MOC_DRIVER_NR_ENROLL_STAGES 10

G_DECLARE_FINAL_TYPE (FpiDeviceSynapticsMoc, fpi_device_synaptics_moc, FPI, DEVICE_SYNAPTICS_MOC, FpDevice)

struct _FpiDeviceSynapticsMoc
{
  FpDevice              parent;

  guint8                cmd_seq_num;
  guint8                last_seq_num;
  FpiSsm               *task_ssm;
  FpiSsm               *cmd_ssm;
  FpiUsbTransfer       *cmd_pending_transfer;
  gboolean              cmd_complete_on_removal;
  gboolean              cmd_suspended;
  guint8                id_idx;

  bmkt_sensor_version_t mis_version;

  gboolean              action_starting;
  GCancellable         *interrupt_cancellable;

  gint                  enroll_stage;
  gboolean              finger_on_sensor;
  GPtrArray            *list_result;


  struct syna_enroll_resp_data enroll_resp_data;
  syna_state_t                 state;
  GError                      *delay_error;
};
