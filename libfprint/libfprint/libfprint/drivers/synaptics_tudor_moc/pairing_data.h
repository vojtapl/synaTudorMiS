/*
 * TODO: header
 */

#pragma once

#include <glib.h>

#define SENSOR_CERT_BYTES_LEN 400

typedef struct {
   guint16 magic;
   guint16 curve;
   char pub_x[68];
   char pub_y[68];
   guint8 cert_type;
   guint16 sign_size;
   char sign[256];

} sensor_cert_t;

gboolean parse_sensor_certificate(guint8 *to_parse, gsize to_parse_len,
                                  sensor_cert_t *parsed_cert);
