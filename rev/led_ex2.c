#include "led_ex2.h"

#include <string.h>

struct led_action {
    guint16 field0;
    guint32 parameter[3];
};

struct led_profile {
    guint32 duration_ms;
    struct led_action action[6];
};

#define ACTION(field, p0, p1, p2) \
    { (guint16)(field), { (guint32)(p0), (guint32)(p1), (guint32)(p2) } }

#define IDLE_ACTION ACTION(0x0000, 0x20000000, 0x00000000, 0x00000000)
#define ZERO_ACTION ACTION(0x0000, 0x00000000, 0x00000000, 0x00000000)

static const struct led_profile profiles[SYNA_LED_EX2_EVENT_COUNT] = {
    [SYNA_LED_EVENT_IDLE] = {
        0,
        { IDLE_ACTION, IDLE_ACTION, IDLE_ACTION,
          IDLE_ACTION, IDLE_ACTION, IDLE_ACTION },
    },
    [SYNA_LED_EVENT_WAITING_FOR_FINGER] = {
        160000,
        {
            ACTION(0xffff, 0x20000505, 0x00000000, 0x00000505),
            ACTION(0xffff, 0x20000505, 0x00000000, 0x00000505),
            ACTION(0xffff, 0x20000505, 0x00000000, 0x00000505),
            ZERO_ACTION, ZERO_ACTION, ZERO_ACTION,
        },
    },
    [SYNA_LED_EVENT_ENROLL_ACCEPTED] = {
        500,
        {
            ACTION(0x01f4, 0x20000507, 0x00000000, 0x00000505),
            IDLE_ACTION,
            ACTION(0x01f4, 0x20000500, 0x00000000, 0x00000000),
            IDLE_ACTION, ZERO_ACTION, ZERO_ACTION,
        },
    },
    [SYNA_LED_EVENT_ENROLL_REJECTED] = {
        1000,
        {
            ACTION(0x01f4, 0x20000107, 0x00000101, 0x00000000),
            IDLE_ACTION,
            ACTION(0x01f4, 0x20000100, 0x00000000, 0x00000000),
            IDLE_ACTION, ZERO_ACTION, ZERO_ACTION,
        },
    },
    [SYNA_LED_EVENT_MATCH_SUCCESS] = {
        500,
        {
            ACTION(0x01f4, 0x20000507, 0x00000000, 0x00000505),
            IDLE_ACTION,
            ACTION(0x01f4, 0x20000500, 0x00000000, 0x00000000),
            IDLE_ACTION, ZERO_ACTION, ZERO_ACTION,
        },
    },
    [SYNA_LED_EVENT_MATCH_FAILURE] = {
        1000,
        {
            ACTION(0x004b, 0x20000107, 0x00000101, 0x00000000),
            ACTION(0x004b, 0x20000001, 0x00000000, 0x00000000),
            ACTION(0x004b, 0x20000101, 0x00000000, 0x00000000),
            ACTION(0x004b, 0x20000001, 0x00000000, 0x00000000),
            ZERO_ACTION, ZERO_ACTION,
        },
    },
};

GBytes *syna_led_ex2_build(guint event)
{
    const struct led_profile *profile;
    GByteArray *out;

    if (event >= SYNA_LED_EX2_EVENT_COUNT)
        return NULL;

    profile = &profiles[event];
    out = g_byte_array_sized_new(SYNA_LED_EX2_LENGTH);

    {
        const guint8 command = SYNA_LED_EX2_COMMAND;
        const guint32 duration = GUINT32_TO_LE(profile->duration_ms);

        g_byte_array_append(out, &command, sizeof command);
        g_byte_array_append(out, (const guint8 *)&duration, sizeof duration);
    }

    for (guint i = 0; i < G_N_ELEMENTS(profile->action); ++i) {
        guint8 action[0x14] = { 0 };
        const guint16 field0 = GUINT16_TO_LE(profile->action[i].field0);
        const guint32 p0 = GUINT32_TO_LE(profile->action[i].parameter[0]);
        const guint32 p1 = GUINT32_TO_LE(profile->action[i].parameter[1]);
        const guint32 p2 = GUINT32_TO_LE(profile->action[i].parameter[2]);

        /* sendLedEx2Cmd copies only these fields from each source action. */
        memcpy(action, &field0, sizeof field0);
        memcpy(action + 4, &p0, sizeof p0);
        memcpy(action + 8, &p1, sizeof p1);
        memcpy(action + 12, &p2, sizeof p2);
        /* action + 2 and action + 16 remain zero, as in the DLL. */

        g_byte_array_append(out, action, sizeof action);
    }

    g_assert_cmpuint(out->len, ==, SYNA_LED_EX2_LENGTH);
    return g_byte_array_free_to_bytes(out);
}
