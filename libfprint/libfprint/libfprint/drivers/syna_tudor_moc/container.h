/*
 * TODO: add header
 */

#include "other_constants.h"
#include <glib.h>

#define CONTAINTER_HEADER_SIZE 6 // id (2) + data_size (4)

typedef enum {
   CONT_TAG_PROPERTY_ID = 4,
   CONT_TAG_PROPERTY_DATA = 5,
} cont_tag_property_t;

typedef enum {
   HOST_DATA_TAG_VERSION = 1,
   HOST_DATA_TAG_PAIRED_DATA = 2,
} host_data_tag_t;

typedef enum {
   PAIR_DATA_TAG_VERSION = 0,
   PAIR_DATA_TAG_HOST_CERT = 1,
   PAIR_DATA_TAG_PRIVATE_KEY = 2,
   PAIR_DATA_TAG_SENSOR_CERT = 3,
   PAIR_DATA_TAG_PUB_KEY_SEC_DATA = 4,
   PAIR_DATA_TAG_SSI_STORAGE_PSK_ID = 5,
} pair_data_tag_t;

typedef enum {
   ENROLL_TAG_TEMPLATE_ID = 0,
   ENROLL_TAG_USER_ID = 1,
   ENROLL_TAG_FINGER_ID = 2,
} enroll_tag_t;

typedef struct {
   guint16 id;
   guint32 data_size;
   guint8 *data;
} container_item_t;

gboolean serialize_container(container_item_t *cont, guint cont_cnt,
                             guint8 **serialized, gsize *serialized_size);

gboolean deserialize_container(const guint8 *serialized,
                               const gsize serialized_size,
                               container_item_t **cont, guint *cont_item_cnt);

gboolean get_container_with_id_index(container_item_t *container,
                                     guint container_cnt, guint8 id,
                                     guint *idx);

gboolean get_enrollment_data_from_serialized_container(
    const guint8 *data, gsize data_size, enrollment_t *enrollment);
