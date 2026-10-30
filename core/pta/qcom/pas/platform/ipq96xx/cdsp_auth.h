/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CDSP_AUTH_H_
#define _CDSP_AUTH_H_

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * struct cdsp_metadata : secure copy of the image metadata (ELF headers and
 * hash segment) a client passed to INIT_IMAGE.
 *
 * @buf:  Secure copy, NULL when there is none.
 * @pa:   Physical address of @buf, as seen by TME-Lite.
 * @size: Size of @buf in bytes.
 */
struct cdsp_metadata {
	void *buf;
	uint32_t pa;
	size_t size;
};

/*
 * cdsp_metadata_save() : copy client metadata into secure memory, replacing
 * any copy @md already holds.
 */
TEE_Result cdsp_metadata_save(struct cdsp_metadata *md, void *src,
			      size_t size);

/* cdsp_metadata_free() : release the copy held by @md, if any. */
void cdsp_metadata_free(struct cdsp_metadata *md);

/*
 * cdsp_image_auth() : authenticate the image described by @md with TME-Lite
 * against @sw_id.
 *
 * The metadata is single use: it is released whatever the outcome, so a
 * retry needs a new INIT_IMAGE.
 */
TEE_Result cdsp_image_auth(struct cdsp_metadata *md, uint32_t sw_id);

#endif /* _CDSP_AUTH_H_ */
