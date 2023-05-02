// SPDX-License-Identifier: BSD-2-Clause
/**
 * Copyright 2017-2021 NXP
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
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <string.h>

/*
 * Define the RNG Data buffer size and number
 */
#define RNG_DATABUF_SIZE	1024
#define RNG_DATABUF_NB		2

/*
 * Define the number of descriptor entry to generate random data
 */
#define RNG_GEN_DESC_ENTRIES	5

/*
 * Status of the data generation
 */
enum rngsta {
	DATA_EMPTY = 0, /* Data bufer empty */
	DATA_ONGOING,   /* Data generation on going */
	DATA_FAILURE,   /* Error during data generation */
	DATA_OK,        /* Data generation complete with success */
};

/*
 * RNG Data generation
 */
struct rngdata {
	struct caam_jobctx jobctx; /* Job Ring Context */
	uint32_t job_id;           /* Job Id enqueued */

	uint8_t *data;           /* Random Data buffer */
	size_t size;             /* Size in bytes of the Random data buffer */
	size_t rdindex;          /* Current data index in the buffer */

	enum rngsta status;      /* Status of the data generation */
};

/*
 * RNG module private data
 */
struct rng_privdata {
	vaddr_t baseaddr;                       /* RNG base address */
	bool instantiated;                      /* RNG instantiated */
	struct rngdata databuf[RNG_DATABUF_NB]; /* RNG Data generation */
	uint8_t dataidx;                        /* Current RNG Data buffer */
};

static struct rng_privdata *rng_privdata;

/* Allocate and initialize module private data */
static enum caam_status do_allocate(void)
{
	struct rngdata *rngdata = NULL;
	unsigned int idx = 0;

	/* Allocate the Module resources */
	rng_privdata = caam_calloc(sizeof(*rng_privdata));
	if (!rng_privdata) {
		RNG_TRACE("Private Data allocation error");
		return CAAM_OUT_MEMORY;
	}

	rng_privdata->instantiated = false;

	/* Allocates the RNG Data Buffers */
	for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
		rngdata = &rng_privdata->databuf[idx];
		rngdata->data = caam_calloc_align(RNG_DATABUF_SIZE);
		if (!rngdata->data)
			return CAAM_OUT_MEMORY;

		rngdata->size = RNG_DATABUF_SIZE;
		rngdata->jobctx.desc = caam_calloc_desc(RNG_GEN_DESC_ENTRIES);
		if (!rngdata->jobctx.desc)
			return CAAM_OUT_MEMORY;
	}

	return CAAM_NO_ERROR;
}

/* Free module private data */
static void do_free(void)
{
	struct rngdata *rng = NULL;
	unsigned int idx = 0;

	if (rng_privdata) {
		for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
			rng = &rng_privdata->databuf[idx];

			/* Check if there is a Job ongoing to cancel it */
			if (atomic_load_u32(&rng->status) == DATA_ONGOING)
				caam_jr_cancel(rng->job_id);

			caam_free_desc(&rng->jobctx.desc);
			caam_free(rng->data);
			rng->data = NULL;
		}

		caam_free(rng_privdata);
		rng_privdata = NULL;
	}
}

#ifdef CFG_NXP_CAAM_RNG_DRV
/*
 * RNG data generation job ring callback completion
 *
 * @jobctx      RNG data JR Job Context
 */
static void rng_data_done(struct caam_jobctx *jobctx)
{
	struct rngdata *rng = jobctx->context;

	RNG_TRACE("RNG Data id 0x%08" PRIx32 " done with status 0x%" PRIx32,
		  rng->job_id, jobctx->status);

	if (JRSTA_SRC_GET(jobctx->status) == JRSTA_SRC(NONE)) {
		atomic_store_u32(&rng->status, DATA_OK);

		/* Invalidate the data buffer to ensure software gets it */
		cache_operation(TEE_CACHEINVALIDATE, rng->data, rng->size);
	} else {
		RNG_TRACE("RNG Data completion in error 0x%" PRIx32,
			  jobctx->status);
		atomic_store_u32(&rng->status, DATA_FAILURE);
	}

	rng->job_id = 0;
	rng->rdindex = 0;
}

/*
 * Prepares the data generation descriptors
 *
 * @rng       Reference to the RNG Data object
 */
static enum caam_status prepare_gen_desc(struct rngdata *rng)
{
	paddr_t paddr = 0;
	uint32_t *desc = NULL;

	/* Convert the buffer virtual address to physical address */
	paddr = virt_to_phys(rng->data);
	if (!paddr)
		return CAAM_FAILURE;

	desc = rng->jobctx.desc;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, RNG_GEN_DATA);
	caam_desc_add_word(desc, FIFO_ST(RNG_TO_MEM, rng->size));
	caam_desc_add_ptr(desc, paddr);

	RNG_DUMPDESC(desc);

	/* Prepare the job context */
	rng->jobctx.context = rng;
	rng->jobctx.callback = rng_data_done;
	return CAAM_NO_ERROR;
}

/*
 * Launches a RNG Data generation
 *
 * @rng      RNG Data context
 */
static enum caam_status do_rng_start(struct rngdata *rng)
{
	enum caam_status ret = CAAM_FAILURE;

	/* Ensure that data buffer is visible from the HW */
	cache_operation(TEE_CACHEFLUSH, rng->data, rng->size);

	rng->job_id = 0;
	atomic_store_u32(&rng->status, DATA_EMPTY);

	ret = caam_jr_enqueue(&rng->jobctx, &rng->job_id);

	if (ret == CAAM_PENDING) {
		atomic_store_u32(&rng->status, DATA_ONGOING);
		ret = CAAM_NO_ERROR;
	} else {
		RNG_TRACE("RNG Job Ring Error 0x%08x", ret);
		atomic_store_u32(&rng->status, DATA_FAILURE);
		ret = CAAM_FAILURE;
	}

	return ret;
}

/* Checks if there are random data available */
static enum caam_status do_check_data(void)
{
	enum caam_status ret = CAAM_FAILURE;
	struct rngdata *rng = NULL;
	uint32_t wait_jobs = 0;
	unsigned int idx = 0;
	unsigned int loop = 4;

	/* Check if there is a RNG Job to be run */
	for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
		rng = &rng_privdata->databuf[idx];
		if (atomic_load_u32(&rng->status) == DATA_EMPTY) {
			RNG_TRACE("Start RNG #%" PRIu32 " data generation",
				  idx);
			ret = do_rng_start(rng);
			if (ret != CAAM_NO_ERROR)
				return CAAM_FAILURE;
		}
	}

	/* Check if the current data buffer contains data */
	rng = &rng_privdata->databuf[rng_privdata->dataidx];

	switch (atomic_load_u32(&rng->status)) {
	case DATA_OK:
		return CAAM_NO_ERROR;

	case DATA_FAILURE:
		return CAAM_FAILURE;

	default:
		/* Wait until one of the data buffer completes */
		do {
			wait_jobs = 0;
			for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
				rng = &rng_privdata->databuf[idx];
				wait_jobs |= rng->job_id;

				if (atomic_load_u32(&rng->status) == DATA_OK) {
					RNG_TRACE("RNG Data buffer #%" PRIu32
						  " ready",
						  idx);
					rng_privdata->dataidx = idx;
					return CAAM_NO_ERROR;
				}
			}

			if (!wait_jobs) {
				RNG_TRACE("There are no Data Buffers ongoing");
				return CAAM_FAILURE;
			}

			/* Need to wait until one of the jobs completes */
			(void)caam_jr_dequeue(wait_jobs, 100);
		} while (loop--);

		break;
	}

	return CAAM_FAILURE;
}

/*
 * Return the requested random data
 *
 * @buf  [out] data buffer
 * @len  number of bytes to returns
 */
static TEE_Result do_rng_read(uint8_t *buf, size_t len)
{
	struct rngdata *rng = NULL;
	size_t remlen = len;
	uint8_t *rngbuf = buf;

	if (!rng_privdata) {
		RNG_TRACE("RNG Driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	if (!rng_privdata->instantiated) {
		RNG_TRACE("RNG Driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	do {
		if (do_check_data() != CAAM_NO_ERROR) {
			RNG_TRACE("No Data available or Error");
			return TEE_ERROR_BAD_STATE;
		}

		rng = &rng_privdata->databuf[rng_privdata->dataidx];
		RNG_TRACE("Context #%" PRIu8
			  " contains %zu data asked %zu (%zu)",
			  rng_privdata->dataidx, rng->size - rng->rdindex,
			  remlen, len);

		/* Check that current context data are available */
		if ((rng->size - rng->rdindex) <= remlen) {
			/*
			 * There is no or just enough data available,
			 * copy all data
			 */
			RNG_TRACE("Copy all available data");
			memcpy(rngbuf, &rng->data[rng->rdindex],
			       rng->size - rng->rdindex);

			remlen -= rng->size - rng->rdindex;
			rngbuf += rng->size - rng->rdindex;
			/* Set the RNG data status as empty */
			atomic_store_u32(&rng->status, DATA_EMPTY);
		} else {
			/* There is enough data in the current context */
			RNG_TRACE("Copy %zu data", remlen);
			memcpy(rngbuf, &rng->data[rng->rdindex], remlen);
			rng->rdindex += remlen;
			remlen = 0;
		}
	} while (remlen);

	return TEE_SUCCESS;
}

/* Initialize the RNG module to generate data */
static enum caam_status caam_rng_init_data(void)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct rngdata *rng = NULL;
	unsigned int idx = 0;

	for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
		rng = &rng_privdata->databuf[idx];
		retstatus = prepare_gen_desc(rng);

		if (retstatus != CAAM_NO_ERROR)
			break;
	}

	return retstatus;
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
	if (retstatus == CAAM_NO_ERROR)
		rng_privdata->instantiated = true;

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

#ifdef CFG_NXP_CAAM_RNG_DRV
	if (retstatus == CAAM_NO_ERROR)
		retstatus = caam_rng_init_data();
#endif

	if (retstatus != CAAM_NO_ERROR)
		do_free();

	return retstatus;
}

#ifdef CFG_NXP_CAAM_RNG_DRV
TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_rng_read(buf, blen);
}

void plat_rng_init(void)
{
}
#endif
