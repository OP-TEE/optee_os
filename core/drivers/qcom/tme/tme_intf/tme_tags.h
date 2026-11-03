/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TME_TAGS_H
#define __TME_TAGS_H

/*
 * CBOR tags of the TME messages. A request carries the tag of its use case,
 * and the TME answers with the same tag, with the same tag and the FIPS
 * indicator set, or with TME_MSG_CBOR_TAG_ERROR.
 */
enum tme_msg_cbor_tag {
	TME_MSG_CBOR_TAG_FUSE_READ = 301,
	TME_MSG_CBOR_TAG_UPDATE_ROLLBACK_VERSION = 307,
	TME_MSG_CBOR_TAG_FUSE_WRITE_MULTIPLE = 316,
	TME_MSG_CBOR_TAG_WRITE_CONFIG_REGISTER = 334,
	/* Largest tag value, it keeps the encoding of a tag in 3 bytes */
	TME_MSG_CBOR_TAG_MAX = 0xFFFF,
	/* Also used to send an error code as a CBOR integer */
	TME_MSG_CBOR_TAG_ERROR = TME_MSG_CBOR_TAG_MAX,
};

#define TME_MSG_TAG_FIPS_INDICATOR_BMSK		0x1
#define TME_MSG_TAG_FIPS_INDICATOR_SHFT		16

/* Set the field FLD of the tag TAG to VAL */
#define TME_MSG_TAG_FVAL(TAG, FLD, VAL) \
	(((TME_MSG_TAG_##FLD##_BMSK & (VAL)) << TME_MSG_TAG_##FLD##_SHFT) | \
	 (TAG))

#endif /* __TME_TAGS_H */
