// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019-2021, 2023 NXP
 */
#include <caam_common.h>
#include <caam_sm.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drivers/caam_extension.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <tee/cache.h>

#ifdef CFG_PHYS_64BIT
#define BLOB_OPERATE_DESC_ENTRIES 12
#else
#define BLOB_OPERATE_DESC_ENTRIES 10
#endif

/* Secure Memory Access Permission allowed */
#define SM_GRP_BLOB BIT32(3) /* Export/Import Secure Memory blobs allowed */

/* Secure Memory Page(s)/Partition definition for DEK Blob generation */
static const struct caam_sm_page_desc dek_sm_page = {
	.partition = 1,
	.page = 3,
	.page_count = 1,
};

TEE_Result caam_dek_generate(const uint8_t *payload, size_t payload_size,
			     uint8_t *dek, size_t dek_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_sm_page_addr dek_sm_addr = { };
	struct caamdmaobj resblob = { };
	struct caam_jobctx jobctx = { };
	uint32_t key_modifier[2] = { };
	uint32_t *desc = NULL;
	unsigned int opflags = 0;

	assert(payload && dek);
	assert(payload_size && dek_size);

	/* Re-allocate output buffer if alignment needed */
	ret = caam_dmaobj_output_sgtbuf(&resblob, dek, dek_size, dek_size);
	if (ret)
		return ret;

	/* Allocate page(s) in one Secure Memory partition */
	ret = caam_sm_alloc(&dek_sm_page, &dek_sm_addr);
	if (ret != CAAM_NO_ERROR) {
		BLOB_TRACE("Secure memory allocation error 0x%" PRIx32, ret);
		goto out;
	}

	/* Copy input data to encapsulate in Secure Memory allocated */
	memcpy((void *)dek_sm_addr.vaddr, payload, payload_size);

	/*
	 * Set the partition access rights for the group #1 to be
	 * a blob export/import
	 */
	caam_sm_set_access_perm(&dek_sm_page, SM_GRP_BLOB, 0);

	/*
	 * Create the key modifier:
	 * 31                    16            8            0
	 * ---------------------------------------------------
	 * | Length of the payload | AES - 0x55 | CCM - 0x66 |
	 * ---------------------------------------------------
	 */
	key_modifier[0] = SHIFT_U32(payload_size, 16) | SHIFT_U32(0x55, 8) |
			  SHIFT_U32(0x66, 0);
	key_modifier[1] = 0;

	/* Allocate the descriptor */
	desc = caam_calloc_desc(BLOB_OPERATE_DESC_ENTRIES);
	if (!desc) {
		BLOB_TRACE("CAAM Context Descriptor Allocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, LD_IMM_OFF(CLASS_2, REG_KEY, 8, 12));
	caam_desc_add_word(desc, key_modifier[0]);
	caam_desc_add_word(desc, key_modifier[1]);
	caam_desc_add_word(desc, SEQ_IN_PTR(payload_size));
	caam_desc_add_ptr(desc, dek_sm_addr.paddr);
	caam_desc_seq_out(desc, &resblob);
	caam_desc_add_word(desc, BLOB_ENCAPS | PROT_BLOB_SEC_MEM | opflags);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, (void *)payload, payload_size);
	caam_dmaobj_cache_push(&resblob);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus) {
		BLOB_TRACE("CAAM Status 0x%08" PRIx32 "", jobctx.status);
		goto out;
	}

	caam_dmaobj_copy_to_orig(&resblob);

	BLOB_TRACE("Done CAAM BLOB from Secure Memory encaps");
	BLOB_DUMPBUF("Blob Output", resblob.orig.data, resblob.orig.length);
out:
	caam_sm_free(&dek_sm_page);
	caam_free_desc(&desc);
	caam_dmaobj_free(&resblob);

	return caam_status_to_tee_result(retstatus);
}
