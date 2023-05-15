// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 Pengutronix, Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <caam_blob.h>
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_trace.h>
#include <caam_utils_mem.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <tee/cache.h>

#define MKVB_SIZE	32

static uint8_t stored_key[MKVB_SIZE];
static bool mkvb_retrieved;

enum caam_status caam_blob_mkvb_init(vaddr_t baseaddr)
{
	struct caam_jobctx jobctx = { };
	enum caam_status res = CAAM_NO_ERROR;
	struct caambuf buf = { };
	uint32_t *desc = NULL;

	assert(!mkvb_retrieved);

	res = caam_calloc_align_buf(&buf, MKVB_SIZE);
	if (res != CAAM_NO_ERROR)
		goto out;

	desc = caam_calloc_desc(8);
	if (!desc) {
		res = CAAM_OUT_MEMORY;
		goto out_buf;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, SEQ_OUT_PTR(32));
	caam_desc_add_ptr(desc, buf.paddr);
	caam_desc_add_word(desc, BLOB_MSTR_KEY);
	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHEFLUSH, buf.data, buf.length);

	jobctx.desc = desc;
	res = caam_jr_enqueue(&jobctx, NULL);

	if (res != CAAM_NO_ERROR) {
		BLOB_TRACE("JR return code: %#"PRIx32, res);
		BLOB_TRACE("MKVB failed: Job status %#"PRIx32, jobctx.status);
	} else {
		cache_operation(TEE_CACHEINVALIDATE, buf.data, MKVB_SIZE);
		BLOB_DUMPBUF("MKVB", buf.data, buf.length);
		memcpy(&stored_key, buf.data, buf.length);
		mkvb_retrieved = true;
	}

out_buf:
	caam_free_desc(&desc);
	caam_free_buf(&buf);
out:
	caam_hal_ctrl_inc_priblob(baseaddr);

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	COMPILE_TIME_ASSERT(sizeof(hwkey->data) <= sizeof(stored_key));

	if (!mkvb_retrieved)
		return TEE_ERROR_SECURITY;

	memcpy(&hwkey->data, &stored_key, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
