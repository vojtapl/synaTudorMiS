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

/*
 * temporary windows pairing data (currently there are no ways of pairing)
 */

#include <glib.h>
#include <gnutls/gnutls.h>

guint8 winbio_sample_sid[] = {
    0x03, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x0c, 0xbb,
    0x01, 0x4e, 0x6d, 0xdd, 0x74, 0xeb, 0x5b, 0x41, 0xeb, 0x98, 0xe9,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// private key exported by palCryptoEccExportPrivateKey
guint8 sample_privkey_k[] = {
    // 0x6a, 0x7f, 0xb2, 0xf8, 0x0d, 0xdf, 0x0c, 0xdf,
    // 0x18, 0xfe, 0x1d, 0x14, 0x4a, 0x80, 0x9f, 0x58,
    // 0xe4, 0x14, 0x8a, 0x80, 0xcb, 0x9a, 0x75, 0xda,
    // 0x82, 0x19, 0x55, 0x06, 0xce, 0x27, 0x1a, 0xf7
    0xf7, 0x1a, 0x27, 0xce, 0x06, 0x55, 0x19, 0x82, 0xda, 0x75, 0x9a,
    0xcb, 0x80, 0x8a, 0x14, 0xe4, 0x58, 0x9f, 0x80, 0x4a, 0x14, 0x1d,
    0xfe, 0x18, 0xdf, 0x0c, 0xdf, 0x0d, 0xf8, 0xb2, 0x7f, 0x6a

};
gnutls_datum_t sample_privkey_k_datum = {.data = sample_privkey_k,
                                         .size = sizeof(sample_privkey_k)};
guint8 sample_privkey_x[] = {
    // 0x3d, 0xf7, 0xe9, 0x67, 0xc0, 0xd8, 0x52, 0x6a,
    // 0xea, 0x3e, 0x08, 0x0b, 0x10, 0x32, 0xc1, 0x7d,
    // 0x90, 0xd3, 0x9e, 0x50, 0x44, 0x44, 0x49, 0x20,
    // 0xbb, 0xad, 0x14, 0xe0, 0xc2, 0xdb, 0xf9, 0xa8
    0xa8, 0xf9, 0xdb, 0xc2, 0xe0, 0x14, 0xad, 0xbb, 0x20, 0x49, 0x44,
    0x44, 0x50, 0x9e, 0xd3, 0x90, 0x7d, 0xc1, 0x32, 0x10, 0x0b, 0x08,
    0x3e, 0xea, 0x6a, 0x52, 0xd8, 0xc0, 0x67, 0xe9, 0xf7, 0x3d

};
gnutls_datum_t sample_privkey_x_datum = {.data = sample_privkey_x,
                                         .size = sizeof(sample_privkey_x)};

guint8 sample_privkey_y[] = {
    // 0x42, 0x8d, 0x94, 0x68, 0x1d, 0x09, 0xa6, 0x7a,
    // 0xa1, 0xb6, 0xa1, 0x86, 0x3d, 0x25, 0x55, 0xc8,
    // 0x7e, 0xa2, 0xfe, 0x18, 0x18, 0x38, 0xfd, 0x28,
    // 0xc8, 0xc9, 0xa6, 0xd5, 0xb0, 0x21, 0xc6, 0xee
    0xee, 0xc6, 0x21, 0xb0, 0xd5, 0xa6, 0xc9, 0xc8, 0x28, 0xfd, 0x38,
    0x18, 0x18, 0xfe, 0xa2, 0x7e, 0xc8, 0x55, 0x25, 0x3d, 0x86, 0xa1,
    0xb6, 0xa1, 0x7a, 0xa6, 0x09, 0x1d, 0x68, 0x94, 0x8d, 0x42

};
gnutls_datum_t sample_privkey_y_datum = {.data = sample_privkey_y,
                                         .size = sizeof(sample_privkey_y)};

// received host certificate from cmd pair
guint8 sample_recv_host_cert[] = {
    0x3f, 0x5f, 0x17, 0x00, 0x3d, 0xf7, 0xe9, 0x67, 0xc0, 0xd8, 0x52, 0x6a,
    0xea, 0x3e, 0x08, 0x0b, 0x10, 0x32, 0xc1, 0x7d, 0x90, 0xd3, 0x9e, 0x50,
    0x44, 0x44, 0x49, 0x20, 0xbb, 0xad, 0x14, 0xe0, 0xc2, 0xdb, 0xf9, 0xa8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x8d, 0x94, 0x68, 0x1d, 0x09, 0xa6, 0x7a, 0xa1, 0xb6, 0xa1, 0x86,
    0x3d, 0x25, 0x55, 0xc8, 0x7e, 0xa2, 0xfe, 0x18, 0x18, 0x38, 0xfd, 0x28,
    0xc8, 0xc9, 0xa6, 0xd5, 0xb0, 0x21, 0xc6, 0xee, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x00,
    0x4d, 0x63, 0x1a, 0x68, 0xa5, 0x8d, 0x4c, 0xff, 0x6f, 0xd2, 0xef, 0x97,
    0x78, 0x09, 0xe8, 0x2f, 0x0f, 0x1d, 0x61, 0xb1, 0xe2, 0xe9, 0xf7, 0xba,
    0x47, 0x7b, 0x6f, 0xdf, 0xb7, 0xd4, 0x05, 0x6c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// received sensor certificate from cmd pair
guint8 sample_sensor_cert[] = {
    0x3f, 0x5f, 0x17, 0x00, 0x32, 0x29, 0x44, 0x49, 0x1e, 0x0e, 0x65, 0x4d,
    0x1f, 0x49, 0xe7, 0x23, 0xa2, 0x33, 0x25, 0x0f, 0x09, 0x9d, 0xdb, 0x99,
    0x47, 0xdb, 0xb2, 0x99, 0x27, 0x4f, 0xe6, 0xb1, 0x6d, 0x6c, 0x88, 0x3f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4e, 0xbf, 0x09, 0x77, 0x46, 0x48, 0x52, 0x1e, 0xee, 0x9b, 0x75, 0x45,
    0x0b, 0x7d, 0x86, 0xb3, 0x2e, 0xa9, 0x8c, 0x11, 0xfc, 0xf3, 0xf4, 0xd5,
    0x65, 0xa2, 0x3c, 0x30, 0x4b, 0x18, 0xbd, 0x86, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00,
    0x30, 0x45, 0x02, 0x20, 0x04, 0x01, 0x61, 0x18, 0xe2, 0x32, 0xd4, 0xc1,
    0xb3, 0x69, 0xd3, 0x20, 0x48, 0x08, 0x36, 0x19, 0xfd, 0x7c, 0x66, 0x5b,
    0x37, 0x2e, 0x13, 0xb3, 0xcf, 0x24, 0xb7, 0xe1, 0xc8, 0xbb, 0x12, 0x29,
    0x02, 0x21, 0x00, 0xdc, 0x4b, 0x3b, 0xdd, 0xff, 0x2b, 0x50, 0x4e, 0x85,
    0xed, 0xba, 0x2d, 0x22, 0xb5, 0xe8, 0xb2, 0x1b, 0x7a, 0x89, 0x05, 0xdb,
    0x1a, 0x0c, 0x52, 0xf4, 0xd0, 0xe4, 0x5b, 0xd4, 0x06, 0x25, 0xca, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};
