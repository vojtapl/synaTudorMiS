/*
 * TODO: add header
 */

#pragma once

#include <glib.h>
#include "drivers_api.h"
#include "synaptics.h"

#define VCSFW_CMD_GET_VERSION 0x01
#define VCSFW_CMD_RESET 0x05
#define VCSFW_CMD_PEEK 0x07
#define VCSFW_CMD_POKE 0x08
#define VCSFW_CMD_PROVISION 0x0e
#define VCSFW_CMD_RESET_OWNERSHIP 0x10
#define VCSFW_CMD_GET_STARTINFO 0x19
#define VCSFW_CMD_LED_EX2 0x39
#define VCSFW_CMD_STORAGE_INFO_GET 0x3e
#define VCSFW_CMD_STORAGE_PART_FORMAT 0x3f
#define VCSFW_CMD_STORAGE_PART_READ 0x40
#define VCSFW_CMD_STORAGE_PART_WRITE 0x41
// non-original name
#define VCSFW_CMD_TLS_DATA 0x44
#define VCSFW_CMD_DB_OBJECT_CREATE 0x47
#define VCSFW_CMD_TAKE_OWNERSHIP_EX2 0x4f
#define VCSFW_CMD_GET_CERTIFICATE_EX 0x50
#define VCSFW_CMD_TIDLE_SET 0x57
// #define exit/enter bootloader mode 0x69
#define VCSFW_CMD_BOOTLDR_PATCH 0x7d
#define VCSFW_CMD_FRAME_READ 0x7f
#define VCSFW_CMD_FRAME_ACQ 0x80
#define VCSFW_CMD_FRAME_FINISH 0x81
#define VCSFW_CMD_FRAME_STATE_GET 0x82
#define VCSFW_CMD_EVENT_CONFIG 0x86
#define VCSFW_CMD_EVENT_READ 0x87
#define VCSFW_CMD_FRAME_STREAM 0x8b
#define VCSFW_CMD_IOTA_FIND 0x8e
#define VCSFW_CMD_PAIR 0x93
#define VCSFW_CMD_ENROLL 0x96
// non-original name
#define VCSFW_CMD_IDENTIFY_MATCH 0x99
// non-original name
#define VCSFW_CMD_GET_IMAGE_METRICS 0x9d
#define VCSFW_CMD_DB2_GET_DB_INFO 0x9e
#define VCSFW_CMD_DB2_GET_OBJECT_LIST 0x9f
#define VCSFW_CMD_DB2_GET_OBJECT_INFO 0xa0
#define VCSFW_CMD_DB2_GET_OBJECT_DATA 0xa1
#define VCSFW_CMD_DB2_WRITE_OBJECT 0xa2
#define VCSFW_CMD_DB2_DELETE_OBJECT 0xa3
// non-original name
#define VCSFW_CMD_DB2_CLEANUP 0xa4
#define VCSFW_CMD_DB2_FORMAT 0xa5
// #define ? 0xa6
// non-original name
#define VCSFW_CMD_RESET_SBL_MODE 0xaa
#define VCSFW_CMD_SSO 0xac
#define VCSFW_CMD_OPINFO_GET 0xae
#define VCSFW_CMD_HW_INFO_GET 0xaf

int
synaptics_secure_connect (FpiDeviceSynapticsMoc *self,
                          guint8 cmd_id,
                          guint8 trans_len,
                          guint8* trans_data,
                          guint8 recv_len,
                          guint8* recv_data);
