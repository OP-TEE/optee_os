// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <kernel/cache_helpers.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <platform_pas.h>
#include <string.h>
#include <tmel_auth.h>
#include <trace.h>

#include "cdsp_auth.h"

TEE_Result cdsp_metadata_save(struct cdsp_metadata *md,
			      const struct pas_metadata *metadata)
{
	paddr_t pa = 0;
	void *buf = NULL;

	if (!metadata || !metadata->data || !metadata->size)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * TME-Lite reads the metadata by physical address at AUTH_AND_RESET,
	 * when the INIT_IMAGE buffer is no longer available: keep a copy.
	 */
	buf = malloc(metadata->size);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	pa = virt_to_phys(buf);
	if (!pa) {
		free(buf);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, metadata->data, metadata->size);
	/* TME-Lite reads the copy from memory, not through our cache */
	dcache_clean_range(buf, metadata->size);

	cdsp_metadata_free(md);
	md->buf = buf;
	md->pa = pa;
	md->size = metadata->size;

	return TEE_SUCCESS;
}

void cdsp_metadata_free(struct cdsp_metadata *md)
{
	free(md->buf);
	md->buf = NULL;
	md->pa = 0;
	md->size = 0;
}

TEE_Result cdsp_image_auth(struct cdsp_metadata *md, uint32_t sw_id)
{
	struct tmel_sec_auth_params params = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!md->buf) {
		EMSG("No metadata for SW ID %"PRIu32", INIT_IMAGE missing",
		     sw_id);
		return TEE_ERROR_BAD_STATE;
	}

	params.sw_id = sw_id;
	params.elf_buf.pa = md->pa;
	params.elf_buf.len = md->size;
	/* The firmware segments sit in the non-secure carveout */
	params.flags = TMEL_AUTH_FLAG_NS_INTEGRITY;

	res = tmel_secure_auth(&params);
	if (res)
		EMSG("SW ID %"PRIu32" authentication failed: %#"PRIx32,
		     sw_id, res);
	else
		DMSG("SW ID %"PRIu32" authenticated", sw_id);

	cdsp_metadata_free(md);

	return res;
}
