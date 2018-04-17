/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_INTERNAL_ABI_H
#define __SKS_INTERNAL_ABI_H

/* Internal format is based on the API IDs */
#include <sks_ta.h>
#include <stddef.h>


/**
 * Serialization of object attributes
 *
 * An object is defined by the list of its attributes among which identifiers
 * for the type of the object (symmetric key, asymmetric key, ...) and the
 * object value (i.e the AES key value). In the end, an object is a list of
 * attributes.
 *
 * SKS uses a serialized format for defining the attributes of an object. The
 * attributes content starts with a header structure header followed by each
 * attributes, stored in serialized fields:
 * - the 32bit identificator of the attribute
 * - the 32bit value attribute byte size
 * - the effective value of the attribute (variable size)
 */
struct sks_ref {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * Header of a serialised memory object inside SKS TA.
 *
 * @blobs_size; byte size of the serialized data
 * @blobs_count; number of items in the blob
 * @class - object class id (from CK litterature): key, certif, etc...
 * @type - object type id, per class, i.e aes or des3 in the key class.
 * @boolpropl - 32bit bitmask storing boolean properties #0 to #31.
 * @boolproph - 32bit bitmask storing boolean properties #32 to #64.
 * @blobs - then starts the blob binary data
 */
struct sks_attrs_head {
	uint32_t blobs_size;
	uint32_t blobs_count;
#ifdef SKS_SHEAD_WITH_TYPE
	uint32_t class;
	uint32_t type;
#endif
#ifdef SKS_SHEAD_WITH_BOOLPROPS
	uint32_t boolpropl;
	uint32_t boolproph;
#endif
	uint8_t blobs[];
};

#endif /*__SKS_INTERNAL_ABI_H*/
