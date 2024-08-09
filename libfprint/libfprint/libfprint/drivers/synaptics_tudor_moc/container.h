/*
 * TODO: add header
 */

#include <glib.h>

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

typedef struct {
   guint16 id;
   guint32 size;
   guint8 *data;
} tag_container_item_t;
