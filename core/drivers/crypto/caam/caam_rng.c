// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2017-2019 NXP
 *
 * @file    caam_rng.c
 *
 * @brief   CAAM Random Number Generator manager.\n
 *          Implementation of RNG functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <atomic.h>
#include <crypto/crypto.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <tee/cache.h>

/* Local includes */
#include "caam_common.h"
#include "caam_jr.h"
#include "caam_rng.h"

/* Utils includes */
#include "utils_mem.h"

/* Hal includes */
#include "hal_rng.h"

/**
 * @brief   Define the RNG Data buffer size and number
 */
#define RNG_DATABUF_SIZE	1024
#define RNG_DATABUF_NB		2

/**
 * @brief   Define the number of descriptor entry to
 *          generate random data
 */
#define RNG_GEN_DESC_ENTRIES	5

/**
 * @brief   Status of the data generation
 */
enum rngsta {
	DATA_EMPTY = 0, ///< Data bufer empty
	DATA_ONGOING,   ///< Data generation on going
	DATA_FAILURE,   ///< Error during data generation
	DATA_OK,		///< Data generation complete with success
};

/**
 * @brief   RNG Data generation
 */
struct rngdata {
	struct jr_jobctx jobctx;  ///< Job Ring Context
	uint32_t         jobId;   ///< Job Id enqueued

	uint8_t *data;            ///< Random Data buffer
	size_t  size;             ///< Size in bytes of the Random data buffer
	size_t  rdindex;          ///< Current data index in the buffer

	enum rngsta status;       ///< Status of the data generation
};

/**
 * @brief   RNG module private data
 */
struct rng_privdata {
	vaddr_t   baseaddr;                ///< RNG base address
	bool      instantiated;            ///< Flag indicating RNG instantiated
	struct rngdata databuf[RNG_DATABUF_NB]; ///< RNG Data generation
	uint8_t   dataidx;                 ///< Current RNG Data buffer
};

static struct rng_privdata *rng_privdata;

/**
 * @brief   allocate and initialize module private data
 *
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_OUT_MEMORY  Allocation error
 */
static enum CAAM_Status do_allocate(void)
{
	struct rngdata *rngdata;
	uint8_t   idx;

	/* Allocate the Module resources */
	rng_privdata = caam_alloc(sizeof(struct rng_privdata));
	if (!rng_privdata) {
		RNG_TRACE("Private Data allocation error");
		return CAAM_OUT_MEMORY;
	}

	rng_privdata->instantiated = false;

	/* Allocates the RNG Data Buffers */
	for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
		rngdata = &rng_privdata->databuf[idx];
		rngdata->data = caam_alloc_align(RNG_DATABUF_SIZE);
		if (!rngdata->data)
			return CAAM_OUT_MEMORY;

		rngdata->size = RNG_DATABUF_SIZE;
		rngdata->jobctx.desc = caam_alloc_desc(RNG_GEN_DESC_ENTRIES);
	}

	return CAAM_NO_ERROR;
}

/**
 * @brief   free module private data
 *
 */
static void do_free(void)
{
	struct rngdata *rng;
	uint8_t        idx;

	if (rng_privdata) {
		for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
			rng = &rng_privdata->databuf[idx];

			/* Check if there is a Job ongoing to cancel it */
			if (atomic_load_u32(&rng->status) == DATA_ONGOING)
				caam_jr_cancel(rng->jobId);

			caam_free_desc(&rng->jobctx.desc);
			caam_free(rng->data);
			rng->data = NULL;
		}

		caam_free(rng_privdata);
		rng_privdata = NULL;
	}
}

#ifdef CFG_CRYPTO_RNG_HW

/**
 * @brief   RNG data generation job ring callback completion
 *
 * @param[in] jobctx      RNG data JR Job Context
 *
 */
static void rng_data_done(struct jr_jobctx *jobctx)
{
	struct rngdata *rng = jobctx->context;

	RNG_TRACE("RNG Data id 0x%08"PRIx32" done with status 0x%"PRIx32"",
				rng->jobId, jobctx->status);

	if (JRSTA_SRC_GET(jobctx->status) == JRSTA_SRC(NONE)) {
		atomic_store_u32(&rng->status, DATA_OK);

		/* Invalidate the data buffer to ensure software got it */
		cache_operation(TEE_CACHEINVALIDATE, rng->data, rng->size);
	} else {
		RNG_TRACE("RNG Data completion in error 0x%"PRIx32"",
			jobctx->status);
		atomic_store_u32(&rng->status, DATA_FAILURE);
	}

	rng->jobId   = 0;
	rng->rdindex = 0;
}

/**
 * @brief   Prepares the data generation descriptors
 *
 * @param[in] rng       Reference to the RNG Data object
 *
 * @retval  CAAM_NO_ERROR     Success
 * @retval  CAAM_FAILURE      General failure
 */
static enum CAAM_Status prepare_gen_desc(struct rngdata *rng)
{
	paddr_t       paddr;
	descPointer_t desc;

	/* Convert the buffer virtual address to physical address */
	paddr = virt_to_phys(rng->data);
	if (!paddr)
		return CAAM_FAILURE;

	desc = rng->jobctx.desc;

	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	desc_add_word(desc, RNG_GEN_DATA);
	desc_add_word(desc, FIFO_ST(RNG_TO_MEM, rng->size));
	desc_add_ptr(desc, paddr);

	RNG_DUMPDESC(desc);

	/* Prepare the job context */
	rng->jobctx.context = rng;
	rng->jobctx.callbk  = rng_data_done;
	return CAAM_NO_ERROR;
}

/**
 * @brief   Launches a RNG Data generation
 *
 * @param[in] rng      RNG Data context
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_FAILURE    General error
 */
static enum CAAM_Status do_rng_start(struct rngdata *rng)
{
	enum CAAM_Status ret;

	/* Ensure that data buffer is flushed */
	cache_operation(TEE_CACHEFLUSH, rng->data, rng->size);

	rng->jobId  = 0;
	atomic_store_u32(&rng->status, DATA_EMPTY);

	ret = caam_jr_enqueue(&rng->jobctx, &rng->jobId);

	if (ret == CAAM_PENDING) {
		atomic_store_u32(&rng->status, DATA_ONGOING);
		ret = CAAM_NO_ERROR;
	} else {
		RNG_TRACE("RNG Job Ring Error 0x%"PRIx32"", ret);
		atomic_store_u32(&rng->status, DATA_FAILURE);
		ret = CAAM_FAILURE;
	}

	return ret;
}

/**
 * @brief   Checks if there are random data available
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_FAILURE    General error
 */
static enum CAAM_Status do_check_data(void)
{
	enum CAAM_Status ret = CAAM_FAILURE;

	struct rngdata *rng;

	uint32_t waitJobs;
	uint8_t  idx;
	uint8_t  loop = 4;

	/* Check if there is a RNG Job to be run */
	for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
		rng = &rng_privdata->databuf[idx];
		if (atomic_load_u32(&rng->status) == DATA_EMPTY) {
			RNG_TRACE("Start RNG #%d data generation", idx);
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

	default:
		/* Wait until one of the data buffer completed */
		do {
			waitJobs = 0;
			for (idx = 0; idx < RNG_DATABUF_NB; idx++) {
				rng = &rng_privdata->databuf[idx];
				waitJobs |= rng->jobId;

				if (atomic_load_u32(&rng->status) == DATA_OK) {
					RNG_TRACE("RNG Data buffer #%d ready",
						idx);
					rng_privdata->dataidx = idx;
					return CAAM_NO_ERROR;
				}
			}

			if (!waitJobs) {
				RNG_TRACE("There are no Data Buffers ongoing");
				return CAAM_FAILURE;
			}

			/* Need to wait until one of the jobs complete */
			ret = caam_jr_dequeue(waitJobs, 100);
		} while (loop--);

		break;
	}

	return CAAM_FAILURE;
}

/**
 * @brief   Returns the requested random data
 *
 * @param[in]  len  number of bytes to returns
 *
 * @param[out] buf  data buffer
 *
 * @retval  TEE_SUCCESS          Success
 * @retval  TEE_ERROR_BAD_STATE  RNG is in incorrect state
 */
static TEE_Result do_rng_read(uint8_t *buf, size_t len)
{
	struct rngdata *rng;

	size_t  remlen  = len;
	uint8_t *rngbuf = buf;

	if (!rng_privdata) {
		RNG_TRACE("RNG Driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	if (rng_privdata->instantiated == false) {
		RNG_TRACE("RNG Driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	do {
		if (do_check_data() != CAAM_NO_ERROR) {
			RNG_TRACE("No Data available or Error");
			return TEE_ERROR_BAD_STATE;
		}

		rng = &rng_privdata->databuf[rng_privdata->dataidx];
		RNG_TRACE("Current Context #%d contains %d data, asked %d (%d)",
					rng_privdata->dataidx,
					(rng->size - rng->rdindex),
					remlen, len);

		/* Check that current context data are available */
		if ((rng->size - rng->rdindex) <= remlen) {
			/*
			 * There is no or just enough data available,
			 * copy all data
			 */
			RNG_TRACE("Copy all available data");
			memcpy(rngbuf, &rng->data[rng->rdindex],
					(rng->size - rng->rdindex));

			remlen -= (rng->size - rng->rdindex);
			rngbuf += (rng->size - rng->rdindex);
			/* Set the RNG data status as empty */
			atomic_store_u32(&rng->status, DATA_EMPTY);
		} else {
			/*
			 * There is enough data in the current context
			 */
			RNG_TRACE("Copy %d data", remlen);
			memcpy(rngbuf, &rng->data[rng->rdindex],
					remlen);
			rng->rdindex += remlen;
			remlen = 0;
		}
	} while (remlen);

	return TEE_SUCCESS;
}

/**
 * @brief   Initialize the RNG module to generate data
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 */
static enum CAAM_Status caam_rng_init_data(void)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	struct rngdata *rng;
	uint8_t        idx;

	for (idx = 0; (idx < RNG_DATABUF_NB); idx++) {
		rng = &rng_privdata->databuf[idx];
		retstatus = prepare_gen_desc(rng);

		if (retstatus != CAAM_NO_ERROR)
			break;
	}

	return retstatus;
}
#endif // CFG_CRYPTO_RNG_HW

/**
 * @brief   Prepares the instantiation descriptor
 *
 * @param[in]     nbSH       Number of the State Handle
 * @param[in]     sh_status  State Handles status
 * @param[in/out] desc       Reference to the descriptor
 */
static void prepare_inst_desc(uint32_t nbSH, uint32_t sh_status,
							 descPointer_t desc)
{
	bool          key_loaded;
	uint8_t       sh_idx    = 0;
	uint8_t       nbMaxSh   = nbSH;

	/* Read the SH and secure key status */
	key_loaded = hal_rng_key_loaded(rng_privdata->baseaddr);
	RNG_TRACE("RNG SH Status 0x%08"PRIx32" - Key Status %d",
					sh_status, key_loaded);

	while (sh_status & (1 << sh_idx))
		sh_idx++;

	RNG_TRACE("Instantiation start at SH%d (%d)", sh_idx, nbMaxSh);

	/* Don't set the descriptor header now */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	/* First State Handle to instantiate */
	desc_add_word(desc, RNG_SH_INST(sh_idx));

	/* Next State Handle */
	sh_idx++;

	while (sh_idx < nbMaxSh) {
		if (!(sh_status & (1 << sh_idx))) {
			/*
			 * If there is more SH to instantiate, add a wait loop
			 * followed by a reset the done status to execute next
			 * command
			 */
			desc_add_word(desc, JUMP_C1_LOCAL(ALL_COND_TRUE,
						JMP_COND(NONE), 1));
			desc_add_word(desc, LD_NOCLASS_IMM(REG_CLEAR_WRITTEN,
						sizeof(uint32_t)));
			desc_add_word(desc, 0x1);
			desc_add_word(desc, RNG_SH_INST(sh_idx));
		}
		/* Next State Handle */
		sh_idx++;
	}

	/* Load the Key if needed */
	if (key_loaded == false) {
		/*
		 * Add a wait loop followed by a reset the done status
		 * to execute next command
		 */
		desc_add_word(desc, JUMP_C1_LOCAL(ALL_COND_TRUE,
				JMP_COND(NONE), 1));
		desc_add_word(desc, LD_NOCLASS_IMM(REG_CLEAR_WRITTEN,
				sizeof(uint32_t)));
		desc_add_word(desc, 0x1);
		desc_add_word(desc, RNG_GEN_SECKEYS);
	}

	RNG_DUMPDESC(desc);
}

/**
 * @brief   Instantiates the RNG State Handles if not already done
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of Memory
 */
enum CAAM_Status caam_rng_instantiation(void)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	struct jr_jobctx jobctx = {0};
	descPointer_t    desc = NULL;
	uint32_t         sh_status;
	uint32_t         nbSH;
	uint32_t         sh_mask;
	uint32_t         inc_delay = 0;

	RNG_TRACE("RNG Instantation");

	/* Check if RNG is already instantiated */
	if (hal_rng_instantiated(rng_privdata->baseaddr)) {
		RNG_TRACE("RNG already instantiated");
		retstatus = CAAM_NO_ERROR;
		goto end_inst;
	}

	/*
	 * RNG needs to be instantiated. Allocate and prepare the
	 * Job Descriptor
	 */

	/* Calculate the State Handles bit mask */
	nbSH = hal_rng_get_nbSH(rng_privdata->baseaddr);
	sh_mask = (1 << nbSH) - 1;

	/*
	 * The maximum size of the descriptor is:
	 *    |----------------------|
	 *    | Header               | = 1
	 *    |----------------------|
	 *    | First instantation   | = 1
	 *    |----------------------|-------------------------
	 *    | wait complete        | = 1
	 *    |----------------------|
	 *    | Clear done status    |       Repeat (nbSH - 1)
	 *    |                      | = 2
	 *    |----------------------|
	 *	  | next SH instantation | = 1
	 *    |----------------------|-------------------------
	 *    | wait complete        | = 1
	 *    |----------------------|
	 *    | Clear done status    | = 2
	 *    |                      |
	 *    |----------------------|
	 *	  | Generate Secure Keys | = 1
	 *    |----------------------|
	 */
	desc = caam_alloc_desc(1 + nbSH + ((nbSH - 1) * 3) + 4 + 1);
	if (!desc) {
		RNG_TRACE("Descriptor Allocation error");
		retstatus = CAAM_OUT_MEMORY;
		goto end_inst;
	}

	jobctx.desc = desc;

	do {
		/* Check if all State Handles are instantiated */
		sh_status  = hal_rng_get_statusSH(rng_privdata->baseaddr);
		if ((sh_status & sh_mask) == sh_mask) {
			RNG_TRACE("RNG All SH are instantiated (0x%08"PRIx32")",
					sh_status);
			retstatus = CAAM_NO_ERROR;
			goto end_inst;
		}

		if (sh_status == 0) {
			retstatus = hal_rng_kick(rng_privdata->baseaddr,
						inc_delay);
			RNG_TRACE("RNG Kick (inc=%d) ret 0x%08"PRIx32"",
						inc_delay, retstatus);
			if (retstatus == CAAM_OUT_OF_BOUND) {
				retstatus = CAAM_FAILURE;
				goto end_inst;
			}
			inc_delay += 200;
		}

		prepare_inst_desc(nbSH, sh_status, desc);

		retstatus = caam_jr_enqueue(&jobctx, NULL);
		RNG_TRACE("RNG Job returned 0x%08"PRIx32"", retstatus);

		if ((retstatus != CAAM_NO_ERROR) &&
				(retstatus != CAAM_JOB_STATUS))
			goto end_inst;

		if (retstatus == CAAM_JOB_STATUS) {
			RNG_TRACE("RNG Job status 0x%08"PRIx32"",
				jobctx.status);
			if ((JRSTA_SRC_GET(jobctx.status) != JRSTA_SRC(CCB)) ||
				(JRSTA_CCB_GET_ERR(jobctx.status) !=
				 (JRSTA_CCB_CHAID_RNG | JRSTA_CCB_ERRID_HW))) {
				retstatus = CAAM_FAILURE;
				goto end_inst;
			} else
				retstatus = CAAM_NO_ERROR;
		}
	} while (retstatus == CAAM_NO_ERROR);

end_inst:
	if (retstatus == CAAM_NO_ERROR)
		rng_privdata->instantiated = true;

	caam_free_desc(&desc);

	RNG_TRACE("RNG Instantiation return 0x%08"PRIx32"", retstatus);

	return retstatus;
}


/**
 * @brief   Initialize the RNG module and do the instantation of the
 *          State Handles if not done
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_rng_init(vaddr_t ctrl_addr)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	RNG_TRACE("Initialization");
	retstatus = do_allocate();
	if (retstatus == CAAM_NO_ERROR) {
		rng_privdata->baseaddr = ctrl_addr;
		retstatus = caam_rng_instantiation();
	}

#ifdef CFG_CRYPTO_RNG_HW
	if (retstatus == CAAM_NO_ERROR)
		retstatus = caam_rng_init_data();
#endif

	if (retstatus != CAAM_NO_ERROR)
		do_free();

	return retstatus;
}

#ifdef CFG_CRYPTO_RNG_HW
/**
 * @brief   Crypto interface used in HW RNG supported
 *          Fills input buffer \a buf with \a blen random bytes
 *
 * @param[in] blen  Number of random bytes to read
 *
 * @param[out] buf  Buffer to fill
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_BAD_STATE       RNG is not in correct state
 * @retval TEE_ERROR_NOT_IMPLEMENTED RNG function is not implemented
 */
TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_rng_read(buf, blen);
}

/**
 * @brief   This function is need by the core/crypto/rng_hw.c file
 *          if CFG_WITH_SOFTWARE_PRNG not defined.
 *          Function is not used if crypto_rng_read function is
 *          re-implemented outside the core/crypto/rng_hw.c file.
 *
 *          Read only one Random byte.
 *
 * @retval random byte read if not error
 */
uint8_t hw_get_random_byte(void)
{
	uint8_t data;

	if (do_rng_read(&data, 1))
		return data;

	return 0;
}
#endif
