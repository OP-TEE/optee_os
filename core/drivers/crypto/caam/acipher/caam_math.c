// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * CAAM Mathematical Operation manager.
 * Implementation of Mathematical operation using CAAM's MATH function
 */
#include <caam_acipher.h>
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_math.h>
#include <mm/core_memprot.h>

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
	struct caamdmaobj res = { };
	struct caamdmaobj data_a = { };
	struct caamdmaobj data_b = { };

	RSA_TRACE("(A xor B) mod n");

	ret = caam_dmaobj_input_sgtbuf(&data_a, data->a.data, data->a.length);
	if (ret)
		return ret;

	ret = caam_dmaobj_input_sgtbuf(&data_b, data->b.data, data->b.length);
	if (ret)
		goto out;

	/*
	 * ReAllocate the result buffer with a maximum size
	 * of the Key Modulus's size (N) if not cache aligned
	 */
	ret = caam_dmaobj_output_sgtbuf(&res, data->result.data,
					data->result.length,
					data->result.length);
	if (ret)
		goto out;

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

	/* Load in A f irst value */
	caam_desc_fifo_load(desc, &data_a, CLASS_1, PKHA_A, NOACTION);
	caam_desc_fifo_load(desc, &data_b, CLASS_1, PKHA_B, NOACTION);

	/* Operation B = A xor B mod n */
	caam_desc_add_word(desc, PKHA_F2M_OP(MOD_ADD_A_B, B));

	/* Store the result */
	caam_desc_fifo_store(desc, &res, PKHA_B);

	caam_dmaobj_cache_push(&data_a);
	caam_dmaobj_cache_push(&data_b);
	caam_dmaobj_cache_push(&res);

	RSA_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		caam_dmaobj_copy_to_orig(&res);
		RSA_DUMPBUF("Output", data->result.data, data->result.length);
		ret = caam_status_to_tee_result(retstatus);
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_free_desc(&desc);
	caam_dmaobj_free(&data_a);
	caam_dmaobj_free(&data_b);
	caam_dmaobj_free(&res);

	return ret;
}

/*
 * Registration of the MATH Driver
 */
static const struct drvcrypt_math driver_math = {
	.xor_mod_n = &do_xor_mod_n,
};

enum caam_status caam_math_init(struct caam_jrcfg *caam_jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t jr_base = caam_jrcfg->base + caam_jrcfg->offset;

	if (caam_hal_ctrl_pknum(jr_base))
		if (!drvcrypt_register_math(&driver_math))
			retstatus = CAAM_NO_ERROR;

	return retstatus;
}
