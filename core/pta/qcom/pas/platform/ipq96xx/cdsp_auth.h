/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CDSP_AUTH_H_
#define _CDSP_AUTH_H_

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*
 * struct cdsp_metadata : secure copy of the image metadata (ELF headers and
 * hash segment) a client passed to INIT_IMAGE.
 *
 * @buf:  Secure copy, NULL when there is none.
 * @pa:   Physical address of @buf.
 * @size: Size of @buf in bytes.
 */
struct cdsp_metadata {
	void *buf;
	paddr_t pa;
	size_t size;
};

struct pas_metadata;

/* cdsp_metadata_save() : save a secure copy of client metadata in @md */
TEE_Result cdsp_metadata_save(struct cdsp_metadata *md,
			      const struct pas_metadata *metadata);

/* cdsp_metadata_free() : release the copy held by @md, if any. */
void cdsp_metadata_free(struct cdsp_metadata *md);

/*
 * cdsp_image_auth() : authenticate @md against @sw_id with TME-Lite. The
 * metadata is single use: released whatever the outcome.
 */
TEE_Result cdsp_image_auth(struct cdsp_metadata *md, uint32_t sw_id);

#endif /* _CDSP_AUTH_H_ */
