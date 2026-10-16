#ifndef SYNA_LED_EX2_H
#define SYNA_LED_EX2_H

#include <glib.h>

#define SYNA_LED_EX2_COMMAND 0x39u
#define SYNA_LED_EX2_LENGTH 0x7du
#define SYNA_LED_EX2_EVENT_COUNT 6u

/* Event indices used by synaWudfBioUsb123.dll. */
enum syna_led_event {
    SYNA_LED_EVENT_IDLE = 0,
    SYNA_LED_EVENT_WAITING_FOR_FINGER = 1,
    SYNA_LED_EVENT_ENROLL_ACCEPTED = 2,
    SYNA_LED_EVENT_ENROLL_REJECTED = 3,
    SYNA_LED_EVENT_MATCH_SUCCESS = 4,
    SYNA_LED_EVENT_MATCH_FAILURE = 5,
};

/*
 * Build the 0x7d-byte VCSFW_CMD_LED_EX2 command for an event index.
 *
 * The returned GBytes owns the complete command payload, including the 0x39
 * command byte. Release it with g_bytes_unref(). Returns NULL for an invalid
 * event index.
 */
GBytes *syna_led_ex2_build(guint event);

#endif
