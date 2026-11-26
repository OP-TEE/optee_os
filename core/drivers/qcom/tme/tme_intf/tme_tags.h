/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TME_TAGS_H
#define __TME_TAGS_H

/* CBOR tags identifying TME operations and generic errors. */
enum tme_msg_cbor_tag {
	TME_MSG_CBOR_TAG_FUSE_READ = 301,
	TME_MSG_CBOR_TAG_UPDATE_ROLLBACK_VERSION = 307,
	TME_MSG_CBOR_TAG_FUSE_WRITE_MULTIPLE = 316,
	TME_MSG_CBOR_TAG_GET_ARB_VERSION = 328,
	TME_MSG_CBOR_TAG_WRITE_CONFIG_REGISTER = 334,
	/* Largest tag value, it keeps the encoding of a tag in 3 bytes */
	TME_MSG_CBOR_TAG_MAX = 0xFFFF,
	/* Also used to send an error code as a CBOR integer */
	TME_MSG_CBOR_TAG_ERROR = TME_MSG_CBOR_TAG_MAX,
};

#endif /* __TME_TAGS_H */
