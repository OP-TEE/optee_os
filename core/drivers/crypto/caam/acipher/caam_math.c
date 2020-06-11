// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * CAAM Mathematical Operation manager.
 * Implementation of Mathematical operation using CAAM's MATH function
 */
#include <caam_acipher.h>
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_math.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "local.h"

/*
 * MATH operation A xor B modulus n
 *
 * @data  [in/out] operation data
 */
static TEE_Result do_xor_mod_n(struct drvcrypt_mod_op *data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	bool realloc = false;
	struct caambuf res_align = { };
	struct caamsgtbuf sgtres = { .sgt_type = false };
	struct caambuf data_a = { .data = data->a.data,
				  .length = data->a.length };
	struct caamsgtbuf sgtdata_a = { .sgt_type = false };
	struct caambuf data_b = { .data = data->b.data,
				  .length = data->b.length };
	struct caamsgtbuf sgtdata_b = { .sgt_type = false };

	RSA_TRACE("(A xor B) mod n");

	data_a.paddr = virt_to_phys(data_a.data);
	data_b.paddr = virt_to_phys(data_b.data);

	if (!data_a.paddr || !data_b.paddr)
		return ret;

	if (!caam_mem_is_cached_buf(data_a.data, data_a.length))
		data_a.nocache = 1;

	retstatus = caam_sgt_build_block_data(&sgtdata_a, NULL, &data_a);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	if (!caam_mem_is_cached_buf(data_b.data, data_b.length))
		data_b.nocache = 1;

	retstatus = caam_sgt_build_block_data(&sgtdata_b, NULL, &data_b);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	/*
	 * ReAllocate the result buffer with a maximum size
	 * of the Key Modulus's size (N) if not cache aligned
	 */
	retstatus = caam_set_or_alloc_align_buf(data->result.data, &res_align,
						data->result.length, &realloc);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	retstatus = caam_sgt_build_block_data(&sgtres, NULL, &res_align);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

#ifdef CFG_CAAM_64BIT
#define XOR_OP_DESC_SIZE 14
#else
#define XOR_OP_DESC_SIZE 11
#endif
	/* Allocate the job descriptor */
	desc = caam_calloc_desc(XOR_OP_DESC_SIZE);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Load in N Modulus Size */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, LD_IMM(CLASS_1, REG_PKHA_N_SIZE, 4));
	caam_desc_add_word(desc, data->n.length);

	/* Load in A first value */
	if (sgtdata_a.sgt_type) {
		caam_desc_add_word(desc, FIFO_LD_SGT(CLASS_1, PKHA_A, NOACTION,
						     sgtdata_a.length));
		caam_desc_add_ptr(desc, virt_to_phys(sgtdata_a.sgt));

		caam_sgt_cache_op(TEE_CACHECLEAN, &sgtdata_a);
	} else {
		caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A, NOACTION,
						 sgtdata_a.length));
		caam_desc_add_ptr(desc, sgtdata_a.buf->paddr);

		if (!sgtdata_a.buf->nocache)
			cache_operation(TEE_CACHECLEAN, sgtdata_a.buf->data,
					sgtdata_a.length);
	}

	/* Load in B second value */
	if (sgtdata_b.sgt_type) {
		caam_desc_add_word(desc, FIFO_LD_SGT(CLASS_1, PKHA_B, NOACTION,
						     sgtdata_b.length));
		caam_desc_add_ptr(desc, virt_to_phys(sgtdata_b.sgt));

		caam_sgt_cache_op(TEE_CACHECLEAN, &sgtdata_b);
	} else {
		caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_B, NOACTION,
						 sgtdata_b.length));
		caam_desc_add_ptr(desc, sgtdata_b.buf->paddr);

		if (!sgtdata_b.buf->nocache)
			cache_operation(TEE_CACHECLEAN, sgtdata_b.buf->data,
					sgtdata_b.length);
	}

	/* Operation B = A xor B mod n */
	caam_desc_add_word(desc, PKHA_F2M_OP(MOD_ADD_A_B, B));

	/* Store the result */
	if (sgtres.sgt_type) {
		caam_desc_add_word(desc, FIFO_ST_SGT(PKHA_B, sgtres.length));
		caam_desc_add_ptr(desc, virt_to_phys(sgtres.sgt));

		caam_sgt_cache_op(TEE_CACHEFLUSH, &sgtres);
	} else {
		caam_desc_add_word(desc, FIFO_ST(PKHA_B, sgtres.length));
		caam_desc_add_ptr(desc, sgtres.buf->paddr);

		if (!sgtres.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, sgtres.buf->data,
					sgtres.length);
	}

	RSA_DUMPDESC(desc);

	if (!res_align.nocache)
		cache_operation(TEE_CACHEFLUSH, res_align.data,
				data->result.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		if (!res_align.nocache)
			cache_operation(TEE_CACHEINVALIDATE, res_align.data,
					data->result.length);

		if (realloc)
			memcpy(data->result.data, res_align.data,
			       data->result.length);

		RSA_DUMPBUF("Output", data->result.data, data->result.length);
		ret = TEE_SUCCESS;
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_free_desc(&desc);

	if (realloc)
		caam_free_buf(&res_align);

	if (sgtdata_a.sgt_type)
		caam_sgtbuf_free(&sgtdata_a);

	if (sgtdata_b.sgt_type)
		caam_sgtbuf_free(&sgtdata_b);

	if (sgtres.sgt_type)
		caam_sgtbuf_free(&sgtres);

	return ret;
}

/*
 * Registration of the MATH Driver
 */
static const struct drvcrypt_math driver_math = {
	.xor_mod_n = &do_xor_mod_n,
};

enum caam_status caam_math_init(vaddr_t ctrl_addr __unused)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (caam_hal_ctrl_pknum(ctrl_addr))
		if (!drvcrypt_register_math(&driver_math))
			retstatus = CAAM_NO_ERROR;

	return retstatus;
}
