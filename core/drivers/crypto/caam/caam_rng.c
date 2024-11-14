// SPDX-License-Identifier: BSD-2-Clause
/**
 * Copyright 2017-2021, 2024 NXP
 *
 * Brief   CAAM Random Number Generator manager.
 *         Implementation of RNG functions.
 */
#include <atomic.h>
#include <caam_common.h>
#include <caam_hal_rng.h>
#include <caam_jr.h>
#include <caam_rng.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <string.h>

/*
 * Define the number of descriptor entry to generate random data
 */
#define RNG_GEN_DESC_ENTRIES	5

/*
 * RNG module private data
 */
struct rng_privdata {
	vaddr_t baseaddr;                       /* RNG base address */
	bool instantiated;                      /* RNG instantiated */
	bool pr_enabled;			/* RNG prediction resistance */
};

static struct rng_privdata *rng_privdata;

/* Allocate and initialize module private data */
static enum caam_status do_allocate(void)
{
	/* Allocate the Module resources */
	rng_privdata = caam_calloc(sizeof(*rng_privdata));
	if (!rng_privdata) {
		RNG_TRACE("Private Data allocation error");
		return CAAM_OUT_MEMORY;
	}

	rng_privdata->instantiated = false;

	return CAAM_NO_ERROR;
}

/* Free module private data */
static void do_free(void)
{
	caam_free(rng_privdata);
	rng_privdata = NULL;
}

#ifdef CFG_NXP_CAAM_RNG_DRV
/*
 * Return the requested random data
 *
 * @buf  [out] data buffer
 * @len  number of bytes to returns
 */
static TEE_Result do_rng_read(uint8_t *buf, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t *desc = NULL;
	uint32_t op = RNG_GEN_DATA;
	void *rng_data = NULL;
	paddr_t paddr = 0;
	struct caam_jobctx jobctx = { };

	if (!rng_privdata) {
		RNG_TRACE("RNG Driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	if (!rng_privdata->instantiated) {
		RNG_TRACE("RNG Driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	rng_data = caam_calloc_align(len);
	if (!rng_data) {
		RNG_TRACE("RNG buffer allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Ensure that data buffer is visible from the HW */
	cache_operation(TEE_CACHEFLUSH, rng_data, len);

	/* Convert the buffer virtual address to physical address */
	paddr = virt_to_phys(rng_data);
	if (!paddr) {
		RNG_TRACE("Virtual/Physical conversion failed");
		goto exit;
	}

	desc = caam_calloc_desc(RNG_GEN_DESC_ENTRIES);
	if (!desc) {
		RNG_TRACE("Descriptor allocation failed");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	if (IS_ENABLED(CFG_CAAM_RNG_RUNTIME_PR) && rng_privdata->pr_enabled)
		op |= ALGO_RNG_PR;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, op);
	caam_desc_add_word(desc, FIFO_ST(CLASS_NO, RNG_TO_MEM, len));
	caam_desc_add_ptr(desc, paddr);

	jobctx.desc = desc;
	RNG_DUMPDESC(desc);

	if (!caam_jr_enqueue(&jobctx, NULL)) {
		cache_operation(TEE_CACHEINVALIDATE, rng_data, len);
		memcpy(buf, rng_data, len);
		ret = TEE_SUCCESS;
	} else {
		RNG_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit:
	caam_free(rng_data);
	caam_free_desc(&desc);
	return ret;
}
#endif /* CFG_NXP_CAAM_RNG_DRV */

/*
 * Prepares the instantiation descriptor
 *
 * @nb_sh      Number of the State Handle
 * @sh_status  State Handles status
 * @desc       Reference to the descriptor
 * @desc       [out] Descriptor filled
 */
static void prepare_inst_desc(uint32_t nb_sh, uint32_t sh_status,
			      uint32_t *desc)
{
	bool key_loaded = false;
	unsigned int sh_idx = 0;
	unsigned int nb_max_sh = nb_sh;

	/* Read the SH and secure key status */
	key_loaded = caam_hal_rng_key_loaded(rng_privdata->baseaddr);
	RNG_TRACE("RNG SH Status 0x%08" PRIx32 " - Key Status %" PRId8,
		  sh_status, key_loaded);

	while (sh_status & BIT(sh_idx))
		sh_idx++;

	RNG_TRACE("Instantiation start at SH%" PRIu32 " (%" PRIu32 ")", sh_idx,
		  nb_max_sh);

	/* Don't set the descriptor header now */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	/* First State Handle to instantiate */
	caam_desc_add_word(desc, RNG_SH_INST(sh_idx));

	/* Next State Handles */
	for (sh_idx++; sh_idx < nb_max_sh; sh_idx++) {
		if (!(sh_status & BIT(sh_idx))) {
			/*
			 * If there is more SH to instantiate, add a wait loop
			 * followed by a reset of the done status to execute
			 * next command
			 */
			caam_desc_add_word(desc,
					   JUMP_C1_LOCAL(ALL_COND_TRUE,
							 JMP_COND(NONE), 1));
			caam_desc_add_word(desc,
					   LD_NOCLASS_IMM(REG_CLEAR_WRITTEN,
							  sizeof(uint32_t)));
			caam_desc_add_word(desc, 0x1);
			caam_desc_add_word(desc, RNG_SH_INST(sh_idx));
		}
	}

	/* Load the Key if needed */
	if (!key_loaded) {
		/*
		 * Add a wait loop while previous operation not completed,
		 * followed by a register clear before executing next command
		 */
		caam_desc_add_word(desc, JUMP_C1_LOCAL(ALL_COND_TRUE,
						       JMP_COND(NONE), 1));
		caam_desc_add_word(desc, LD_NOCLASS_IMM(REG_CLEAR_WRITTEN,
							sizeof(uint32_t)));
		caam_desc_add_word(desc, 0x1);
		caam_desc_add_word(desc, RNG_GEN_SECKEYS);
	}

	RNG_DUMPDESC(desc);
}

enum caam_status caam_rng_instantiation(void)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t sh_status = 0;
	uint32_t nb_sh = 0;
	uint32_t sh_mask = 0;
	uint32_t inc_delay = 0;

	RNG_TRACE("RNG Instantation");

	/* Check if RNG is already instantiated */
	retstatus = caam_hal_rng_instantiated(rng_privdata->baseaddr);

	/* RNG is already instantiated or an error occurred */
	if (retstatus != CAAM_NOT_INIT)
		goto end_inst;

	/*
	 * RNG needs to be instantiated. Allocate and prepare the
	 * Job Descriptor
	 */

	/* Calculate the State Handles bit mask */
	nb_sh = caam_hal_rng_get_nb_sh(rng_privdata->baseaddr);
	sh_mask = GENMASK_32(nb_sh - 1, 0);

	/*
	 * The maximum size of the descriptor is:
	 *    |----------------------|
	 *    | Header               | = 1
	 *    |----------------------|
	 *    | First instantation   | = 1
	 *    |----------------------|-------------------------
	 *    | wait complete        | = 1
	 *    |----------------------|
	 *    | Clear done status    |       Repeat (nb_sh - 1)
	 *    |                      | = 2
	 *    |----------------------|
	 *    | next SH instantation | = 1
	 *    |----------------------|-------------------------
	 *    | wait complete        | = 1
	 *    |----------------------|
	 *    | Clear done status    | = 2
	 *    |                      |
	 *    |----------------------|
	 *    | Generate Secure Keys | = 1
	 *    |----------------------|
	 *    | Pad with a 0         | = 1
	 */
	desc = caam_calloc_desc(2 + (nb_sh - 1) * 4 + 4 + 1);
	if (!desc) {
		RNG_TRACE("Descriptor Allocation error");
		retstatus = CAAM_OUT_MEMORY;
		goto end_inst;
	}

	jobctx.desc = desc;

	do {
		/* Check if all State Handles are instantiated */
		sh_status = caam_hal_rng_get_sh_status(rng_privdata->baseaddr);
		if ((sh_status & sh_mask) == sh_mask) {
			RNG_TRACE("RNG All SH are instantiated (0x%08" PRIx32
				  ")",
				  sh_status);
			retstatus = CAAM_NO_ERROR;
			goto end_inst;
		}

		if (sh_status == 0) {
			retstatus = caam_hal_rng_kick(rng_privdata->baseaddr,
						      inc_delay);
			RNG_TRACE("RNG Kick (inc=%" PRIu32 ") ret 0x%08x",
				  inc_delay, retstatus);
			if (retstatus != CAAM_NO_ERROR) {
				retstatus = CAAM_FAILURE;
				goto end_inst;
			}
			inc_delay += 200;
		}

		prepare_inst_desc(nb_sh, sh_status, desc);

		retstatus = caam_jr_enqueue(&jobctx, NULL);
		RNG_TRACE("RNG Job returned 0x%08x", retstatus);

		if (retstatus != CAAM_NO_ERROR &&
		    retstatus != CAAM_JOB_STATUS)
			goto end_inst;

		if (retstatus == CAAM_JOB_STATUS) {
			RNG_TRACE("RNG Job status 0x%08" PRIx32, jobctx.status);
			if ((JRSTA_SRC_GET(jobctx.status) != JRSTA_SRC(CCB)) ||
			    (JRSTA_CCB_GET_ERR(jobctx.status) !=
			     (JRSTA_CCB_CHAID_RNG | JRSTA_CCB_ERRID_HW)))
				retstatus = CAAM_FAILURE;
			else
				retstatus = CAAM_NO_ERROR;
		}
	} while (retstatus == CAAM_NO_ERROR);

end_inst:
	if (retstatus == CAAM_NO_ERROR) {
		rng_privdata->instantiated = true;
		rng_privdata->pr_enabled =
			caam_hal_rng_pr_enabled(rng_privdata->baseaddr) &
			IS_ENABLED(CFG_CAAM_RNG_RUNTIME_PR);

		RNG_TRACE("RNG prediction resistance is %sabled",
			  rng_privdata->pr_enabled ? "en" : "dis");
	}

	caam_free_desc(&desc);

	RNG_TRACE("RNG Instantiation return 0x%08x", retstatus);

	return retstatus;
}

enum caam_status caam_rng_init(vaddr_t ctrl_addr)
{
	enum caam_status retstatus = CAAM_FAILURE;

	RNG_TRACE("Initialization");
	retstatus = do_allocate();
	if (retstatus == CAAM_NO_ERROR) {
		rng_privdata->baseaddr = ctrl_addr;
		retstatus = caam_rng_instantiation();
	}

	if (retstatus != CAAM_NO_ERROR)
		do_free();

	return retstatus;
}

#ifdef CFG_NXP_CAAM_RNG_DRV
#ifdef CFG_WITH_SOFTWARE_PRNG
void plat_rng_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t buf[64] = { };

	res = do_rng_read(buf, sizeof(buf));
	if (res) {
		EMSG("Failed to read RNG: %#" PRIx32, res);
		panic();
	}

	res = crypto_rng_init(buf, sizeof(buf));
	if (res) {
		EMSG("Failed to initialize RNG: %#" PRIx32, res);
		panic();
	}

	RNG_TRACE("PRNG seeded from CAAM");
}
#else /* !CFG_WITH_SOFTWARE_PRNG */
TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_rng_read(buf, blen);
}

void plat_rng_init(void)
{
}
#endif /* CFG_WITH_SOFTWARE_PRNG */
#endif /* CFG_NXP_CAAM_RNG_DRV */
