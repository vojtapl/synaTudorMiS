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

typedef enum {
   COMM_STATE_SEND = 0,
   COMM_STATE_RECV,

   COMM_NUM_STATES,
} FpCommState;

// Task SSMs ------------------------------------------------------------------

typedef enum {
   INIT_SEND_GET_VERSION = 0,
   INIT_GET_BOOTLOADER_STATE,
   INIT_NUM_STATES,
} FpInitState;

typedef enum {
   CLOSE_NUM_STATES,
} FpCloseState;

typedef enum {
   ENROLL_NUM_STATES,
} FpEnrollState;

typedef enum {
   VERIFY_NUM_STATES,
} FpVerifyState;

typedef enum {
   IDENTIFY_STATE_CAPTURE_FRAME = 0,
   IDENTIFY_STATE_GET_IMAGE_QUALITY,
   IDENTIFY_STATE_CHECK_IMAGE_QUALITY,
   IDENTIFY_STATE_IDENTIFY_MATCH,
   IDENTIFY_NUM_STATES,
} FpIdentifyState;

typedef enum {
   CAPTURE_NUM_STATES,
} FpCaptureState;

typedef enum {
   LIST_NUM_STATES,
} FpListState;

typedef enum {
   DELETE_NUM_STATES,
} FpDeleteState;

typedef enum {
   CLEAR_STORAGE_NUM_STATES,
} FpClearStorageState;

typedef enum {
   CANCEL_NUM_STATES,
} FpCancelState;

typedef enum {
   SUSPEND_NUM_STATES,
} FpSuspendState;

typedef enum {
   RESUME_NUM_STATES,
} FpResumeState;
