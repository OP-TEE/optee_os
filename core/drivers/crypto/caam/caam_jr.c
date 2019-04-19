// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_jr.c
 *
 * @brief   CAAM Job Rings manager.\n
 *          Implementation of functions to enqueue/dequeue CAAM Job Descriptor
 */

/* Global includes */
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>

/* Local includes */
#include "caam_common.h"
#include "caam_io.h"
#include "caam_jr.h"
#include "caam_rng.h"

/* Utils includes */
#include "utils_delay.h"
#include "utils_mem.h"

/* Hal includes */
#include "hal_jr.h"

/**
 * @brief  Enable the interrupt mode or not
 */
#ifdef CFG_CRYPTO_DRIVER
//#define IT_MODE
#endif

/**
 * @brief   Definition of input ring object
 */
struct inring_entry {
	descEntry_t desc; ///< Physical address of the descriptor
};

/**
 * @brief   Definition of output ring object
 */
struct __attribute__((__packed__)) outring_entry {
	descEntry_t  desc;   ///< Physical address of the descriptor
	descStatus_t status; ///< Status of the executed job
};

/**
 * @brief   Job Free define
 */
#define JR_JOB_FREE	0

/**
 * @brief   Caller information context object
 */
struct caller_info {
	struct jr_jobctx   *jobctx;  ///< Caller job context object
	uint32_t      jobid;    ///< Current Job Id
	descEntry_t   pdesc;    ///< Physical address of the descriptor
};

/**
 * @brief   Job Ring module private data
 *
 */
struct jr_privdata {
	vaddr_t baseaddr;               ///< Job Ring base address

	vaddr_t ctrladdr;               ///< CAAM virtual base address
	paddr_t jroffset;               ///< Job Ring address offset
	uint64_t paddr_inrings;         ///< Physical address of input queue
	uint64_t paddr_outrings;        ///< Physical address of output queue

	uint8_t nbJobs;                 ///< Number of Job ring entries managed

	/* Input Job Ring Variables */
	struct inring_entry *inrings;   ///< Input JR HW queue
	unsigned int   inlock;          ///< Input JR spin lock
	uint16_t       inwrite_index;   ///< SW Index - next JR entry free

	/* Output Job Ring Variables */
	struct outring_entry *outrings; ///< Output JR HW queue
	unsigned int    outlock;        ///< Output JR spin lock
	uint16_t        outread_index;  ///< SW Index - next JR output completed

	/* Caller Information Variables */
	struct caller_info *callers;    ///< Job Ring Caller information
	unsigned int    callers_lock;   ///< Job Ring Caller spin lock

	struct itr_handler it_handler;  ///< Interrupt handler
};

/**
 * @brief   Job Ring module private data reference
 */
static struct jr_privdata *jr_privdata;

/**
 * @brief   Free module resources
 *
 * @param[in] jr_priv   Reference to the module private data
 */
static void do_jr_free(struct jr_privdata *jr_priv)
{
	if (jr_priv) {
		caam_free(jr_priv->inrings);
		caam_free(jr_priv->outrings);
		caam_free(jr_priv->callers);
		caam_free(jr_priv);
	}
}

/**
 * @brief   Allocate module resources
 *
 * @param[in] jr_priv   Reference to the module private data
 * @param[in] nbJobs    Number of jobs to manage in the queue
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
static enum CAAM_Status do_jr_alloc(struct jr_privdata **privdata,
					uint8_t nbJobs)
{
	enum CAAM_Status retstatus = CAAM_OUT_MEMORY;
	struct jr_privdata *jr_priv = NULL;

	/* Allocate the Job Ring private data */
	jr_priv = caam_alloc(sizeof(struct jr_privdata));

	if (!jr_priv) {
		JR_TRACE("Private Data allocation error");
		goto end_alloc;
	}

	/* Setup the number of jobs */
	jr_priv->nbJobs = nbJobs;

	/* Allocate the input and output job ring queues */
	jr_priv->inrings  = caam_alloc_align(nbJobs *
						sizeof(struct inring_entry));
	jr_priv->outrings = caam_alloc_align(nbJobs *
						sizeof(struct outring_entry));

	/* Allocate the callers information */
	jr_priv->callers  = caam_alloc(nbJobs * sizeof(struct caller_info));

	if ((!jr_priv->inrings) || (!jr_priv->outrings) ||
		(!jr_priv->callers)) {
		JR_TRACE("JR resources allocation error");
		goto end_alloc;
	}

	/* Initialize the spin locks */
	jr_priv->inlock   = SPINLOCK_UNLOCK;
	jr_priv->outlock  = SPINLOCK_UNLOCK;
	jr_priv->callers_lock = SPINLOCK_UNLOCK;

	/* Initialize the queue counter */
	jr_priv->inwrite_index = jr_priv->outread_index = 0;

	/*
	 * Ensure that allocated queue initialization is pushed to the physical
	 * memory
	 */
	cache_operation(TEE_CACHEFLUSH, jr_priv->inrings,
					nbJobs * sizeof(struct inring_entry));
	cache_operation(TEE_CACHEFLUSH, jr_priv->outrings,
					nbJobs * sizeof(struct outring_entry));

	retstatus = CAAM_NO_ERROR;
end_alloc:
	if (retstatus != CAAM_NO_ERROR)
		do_jr_free(jr_priv);
	else
		*privdata = jr_priv;

	return retstatus;
}

/**
 * @brief   Job Ring Interrupt handler
 *
 * @param[in]  handler  Interrupt Handler structure
 *
 * @retval ITRR_HANDLED  Interrupt has been handled
 */
static enum itr_return caam_jr_irqhandler(struct itr_handler *handler)
{
	struct jr_privdata *jrpriv = handler->data;

	JR_TRACE("Disable the interrupt");
	itr_disable(jrpriv->it_handler.it);

	sev();

	return ITRR_HANDLED;
}


/**
 * @brief   Dequeues all Jobs completed. Call the job context callback
 *          function. Function returns the bit maks of the completed job
 *          expected (\a waitJobIds parameter)
 *
 * @param[in] waitJobIds  Expected Jobs to be complete
 *
 * @retval  Bit mask of the jobs completed function of input parameter
 */
static uint32_t do_jr_dequeue(uint32_t waitJobIds)
{
	uint32_t retJobId = 0;

	struct caller_info   *caller;
	struct outring_entry *jr_out;
	struct jr_jobctx     *jobctx;
	uint32_t  exceptions;
	int       found;
	uint16_t  idx_jr;
	uint16_t  nbJobs_done;
	size_t    nbJobs_inv;

	exceptions = cpu_spin_lock_xsave(&jr_privdata->inlock);

	nbJobs_done = hal_jr_get_nbJobDone(jr_privdata->baseaddr);

	if (nbJobs_done == 0) {
		cpu_spin_unlock_xrestore(&jr_privdata->inlock, exceptions);
		return retJobId;
	}

	/* Ensure that output ring descriptor entries are not in cache */
	if ((jr_privdata->outread_index + nbJobs_done) > jr_privdata->nbJobs) {
		/* Invalidate all job buffer */
		/* Some job completed are at before the current outread_index */
		jr_out     = jr_privdata->outrings;
		nbJobs_inv = jr_privdata->nbJobs;
	} else {
		/* Invalidate only the job index completed */
		jr_out = &jr_privdata->outrings[jr_privdata->outread_index];
		nbJobs_inv = nbJobs_done;
	}

	cache_operation(TEE_CACHEINVALIDATE, (void *)jr_out,
			(sizeof(struct outring_entry) * nbJobs_inv));

	do {
		jr_out = &jr_privdata->outrings[jr_privdata->outread_index];

		/*
		 * Lock the caller information array because enqueue is
		 * also touching it
		 */
		cpu_spin_lock(&jr_privdata->callers_lock);
		for ((idx_jr = 0), (found = (-1));
				(idx_jr < jr_privdata->nbJobs) && (found < 0);
				idx_jr++) {
			/*
			 * Search for the caller information corresponding to
			 * the completed JR.
			 * Don't use the outread_index or inwrite_index because
			 * completion can be out of order compared to input
			 * buffer
			 */
			caller = &jr_privdata->callers[idx_jr];
			if (caam_read_val(&jr_out->desc) == caller->pdesc) {
				jobctx         = caller->jobctx;
				jobctx->status = caam_read_val(&jr_out->status);

				/* Update return Job Id mask */
				if (caller->jobid & waitJobIds)
					retJobId |= caller->jobid;

				JR_TRACE("JR id=%d, context @0x%08"PRIxVA"",
					caller->jobid, (vaddr_t)jobctx);
				/* Clear the Entry Descriptor DMA */
				caller->pdesc = 0;
				caller->jobid = JR_JOB_FREE;
				found = idx_jr;
				JR_TRACE("Free space #%d in the callers array",
					idx_jr);
			}
		}
		cpu_spin_unlock(&jr_privdata->callers_lock);

		/*
		 * Remove the JR from the output list even if no
		 * JR caller found
		 */
		hal_jr_del_job(jr_privdata->baseaddr);

		/*
		 * Increment index to next JR output entry taking care that
		 * is a circular buffer of nbJobs size.
		 */
		jr_privdata->outread_index++;
		jr_privdata->outread_index %= jr_privdata->nbJobs;

		if ((found >= 0) && (jobctx->callbk)) {
			/* Finally, execute user's callback */
			jobctx->callbk(jobctx);
		}

	} while (--nbJobs_done);

	cpu_spin_unlock_xrestore(&jr_privdata->inlock, exceptions);

	return retJobId;
}

/**
 * @brief  Enqueues a new job in the Job Ring input queue. Keep the caller's
 *         job context in private array.
 *
 * @param[in]  jobctx   Caller's job context
 * @param[out] jobId    Job Id enqueued
 *
 * @retval  CAAM_NO_ERROR  Success
 * @retval  CAAM_BUSY      CAAM is busy
 */
static enum CAAM_Status do_jr_enqueue(struct jr_jobctx *jobctx, uint32_t *jobId)
{
	enum CAAM_Status retstatus = CAAM_BUSY;

	struct caller_info *caller = NULL;
	uint32_t exceptions;
	uint32_t job_mask = 0;
	uint8_t  idx_jr;
	bool     found;

	exceptions = cpu_spin_lock_xsave(&jr_privdata->inlock);

	/* Stay lock until a job is available */
	/* Check if there is an available JR index in the HW */
	while (hal_jr_read_nbSlotAvailable(jr_privdata->baseaddr) == 0) {
		/*
		 * WFE will be exit be a SEV generated but the
		 * interrupt handler or by a spin_unlock
		 */
		wfe();
	};

	/*
	 * There is a space free in the input ring but it doesn't mean
	 * that the job pushed is completed.
	 * Completion is out of order. Look for a free space in the
	 * caller data to push them and get a job id for the completion
	 *
	 * Lock the caller information array because dequeue is
	 * also touching it
	 */
	cpu_spin_lock(&jr_privdata->callers_lock);
	for ((idx_jr = 0), (found = false);
			(idx_jr < jr_privdata->nbJobs) && (!found); idx_jr++) {
		if (jr_privdata->callers[idx_jr].jobid == JR_JOB_FREE) {
			JR_TRACE("Found a space #%d free in the callers array",
				idx_jr);
			job_mask = 1 << idx_jr;

			/* Store the caller information for the JR completion */
			caller = &jr_privdata->callers[idx_jr];
			caller->jobid  = job_mask;
			caller->jobctx = jobctx;
			caller->pdesc  = virt_to_phys((void *)jobctx->desc);

			found = true;
		}
	}
	cpu_spin_unlock(&jr_privdata->callers_lock);

	if (!found) {
		JR_TRACE("Error didn't find a free space in the callers array");
		goto end_enqueue;
	}

	JR_TRACE("Push id=%d, job (0x%08x) context @0x%08"PRIxVA"",
			jr_privdata->inwrite_index, job_mask, (vaddr_t)jobctx);

	/* Push the descriptor into the JR HW list */
	caam_write_val(&(jr_privdata->inrings[jr_privdata->inwrite_index]),
		caller->pdesc);

	/* Ensure that physical memory is up to date */
	cache_operation(
		TEE_CACHECLEAN,
		(void *)(&jr_privdata->inrings[jr_privdata->inwrite_index]),
		sizeof(struct inring_entry));

	/*
	 * Increment index to next JR input entry taking care that
	 * is a circular buffer of nbJobs size.
	 */
	jr_privdata->inwrite_index++;
	jr_privdata->inwrite_index %= jr_privdata->nbJobs;

	/* Ensure that input descriptor is pushed in physical memory */
	cache_operation(TEE_CACHECLEAN, (void *)jobctx->desc,
				DESC_SZBYTES(desc_get_len(jobctx->desc)));

	/* Inform HW that a new JR is available */
	hal_jr_add_newjob(jr_privdata->baseaddr);

	*jobId = job_mask;
	retstatus = CAAM_NO_ERROR;

#ifdef IT_MODE
	/* Enable JR interrupt */
	JR_TRACE("Enable the interrupt");
	itr_enable(jr_privdata->it_handler.it);
#endif

end_enqueue:
	cpu_spin_unlock_xrestore(&jr_privdata->inlock, exceptions);

	return retstatus;
}

/**
 * @brief   Synchronous job completion callback
 *
 * @param[in] jobctx   Job context
 *
 */
static void job_done(struct jr_jobctx *jobctx)
{
	jobctx->completion = true;
}

/**
 * @brief   Cancels a job id. Remove the job from SW Job array
 *
 * @param[in] jobId      Job Id
 *
 */
void caam_jr_cancel(uint32_t jobId)
{
	uint8_t idx;

	JR_TRACE("Job cancel 0x%"PRIx32"", jobId);
	for (idx = 0; idx < jr_privdata->nbJobs; idx++) {
		/*
		 * Search for the caller information corresponding to
		 * the jobIds mask.
		 */
		if (jr_privdata->callers[idx].jobid == jobId) {
			/* Clear the Entry Descriptor */
			jr_privdata->callers[idx].pdesc = 0;
			jr_privdata->callers[idx].jobid = JR_JOB_FREE;
			return;
		}
	}
}

/**
 * @brief   Checks if one of the given job ids in bit mask format
 *          is complete. If none are complete, wait until timeout expired.
 *          Wait infinitively is \a timeout_ms = (-1)
 *
 * @param[in] jobIds     Job Ids Mask
 * @param[in] timeout_ms timeout in millisecond
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_TIMEOUT     Operation timeout
 */
enum CAAM_Status caam_jr_dequeue(uint32_t jobIds, uint32_t timeout_ms)
{
	uint32_t jobComplete;
	uint32_t nbTimeWait = 0;
	bool     infinite = false;

	if (timeout_ms == (uint32_t)(-1)) {
		infinite = true;
	} else {
		/* Divide the timeout_ms in 10 ms wait time */
		nbTimeWait = timeout_ms / 10;
	}

	do {
		/* Call the do_jr_dequeue function to dequeue the jobs */
		jobComplete = do_jr_dequeue(jobIds);

		if (jobComplete & jobIds)
			return CAAM_NO_ERROR;

		/* Check if JR interrupt otherwise wait a bit */
		if (!hal_jr_poolackIT(jr_privdata->baseaddr)) {
#ifdef IT_MODE
			wfe();
#else
			caam_udelay(10);
#endif
		}
	} while (infinite || (nbTimeWait--));

	return CAAM_TIMEOUT;
}

/**
 * @brief   Enqueues a job in the Job Ring input queue and either
 *          wait until job completion or if job is asynchrnous,
 *          returns immediately (if status success, the output
 *          parameter \a jobId is filled with the Job Id pushed)
 *
 * @param[in] jobctx  Reference to the job context
 *
 * @param(out] jobId  If pointer not NULL, job is asynchronous and
 *                    jobId contains the Job Id enqueued
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_BAD_PARAM   Bad parameters
 * @retval  CAAM_BUSY        Operation cancelled, system is busy
 * @retval  CAAM_PENDING     Operation is pending
 * @retval  CAAM_TIMEOUT     Operation timeout
 * @retval  CAAM_JOB_STATUS  A job status is available
 */
enum CAAM_Status caam_jr_enqueue(struct jr_jobctx *jobctx, uint32_t *jobId)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
#ifdef TIMEOUT_COMPLETION
	int      timeout   = 10;  // Number of loop to pool job completion
#endif

	if (!jobctx)
		return CAAM_BAD_PARAM;

	JR_DUMPDESC(jobctx->desc);

	if ((!jobctx->callbk) && (jobId)) {
		JR_TRACE("Job Callback not defined whereas asynchronous");
		return CAAM_BAD_PARAM;
	}

	if ((jobctx->callbk) && (!jobId)) {
		JR_TRACE("Job Id not defined whereas asynchronous");
		return CAAM_BAD_PARAM;
	}

	jobctx->completion = false;
	jobctx->status     = 0;

	/*
	 * If parameter jobId is NULL, the job is synchronous, hence use
	 * the local job_done callback function
	 */
	if ((!jobctx->callbk) && (!jobId)) {
		jobctx->callbk  = job_done;
		jobctx->context = jobctx;
	}

	retstatus = do_jr_enqueue(jobctx, &jobctx->jobId);

	if (retstatus != CAAM_NO_ERROR) {
		JR_TRACE("enqueue job error 0x%08"PRIx32"", retstatus);
		return retstatus;
	}

	/*
	 * If parameter jobId is defined, the job is asynchronous, so
	 * returns with setting the jobId value
	 */
	if (jobId) {
		*jobId = jobctx->jobId;
		return CAAM_PENDING;
	}

#ifdef TIMEOUT_COMPLETION
	/*
	 * Job is synchronous wait until job complete or timeout
	 */
	while ((jobctx->completion == false) && (timeout--))
		caam_jr_dequeue(jobctx->jobId, 100);

	if (timeout <= 0) {
		/* Job timeout, cancel it and return in error */
		caam_jr_cancel(jobctx->jobId);
		retstatus = CAAM_TIMEOUT;
	} else {
		if (JRSTA_SRC_GET(jobctx->status) != JRSTA_SRC(NONE))
			retstatus = CAAM_JOB_STATUS;
		else
			retstatus = CAAM_NO_ERROR;
	}
#else
	/*
	 * Job is synchronous wait until job complete
	 * Don't use a timeout because there is no HW timer and
	 * so the timeout in not precise
	 */
	while (jobctx->completion == false)
		caam_jr_dequeue(jobctx->jobId, 100);

	if (JRSTA_SRC_GET(jobctx->status) != JRSTA_SRC(NONE))
		retstatus = CAAM_JOB_STATUS;
	else
		retstatus = CAAM_NO_ERROR;

	/* Erase local callback function */
	jobctx->callbk = NULL;
#endif

	return retstatus;
}

/**
 * @brief   Initialization of the CAAM Job Ring module
 *
 * @param[in] jr_cfg  Job Ring Configuration
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_jr_init(struct jr_cfg *jr_cfg)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	JR_TRACE("Initialization");

	/* Allocate the Job Ring resources */
	retstatus = do_jr_alloc(&jr_privdata, jr_cfg->nb_jobs);
	if (retstatus != CAAM_NO_ERROR)
		goto end_init;

	jr_privdata->ctrladdr = jr_cfg->base;
	jr_privdata->jroffset = jr_cfg->offset;

	retstatus = hal_jr_setowner(jr_cfg->base, jr_cfg->offset,
								JROWN_ARM_S);
	JR_TRACE("JR setowner returned 0x%"PRIx32"", retstatus);

	if (retstatus != CAAM_NO_ERROR)
		goto end_init;

	jr_privdata->baseaddr = jr_cfg->base + jr_cfg->offset;
	retstatus = hal_jr_reset(jr_privdata->baseaddr);
	if (retstatus != CAAM_NO_ERROR)
		goto end_init;

	jr_privdata->paddr_inrings  = (uint64_t)virt_to_phys(
			jr_privdata->inrings);
	jr_privdata->paddr_outrings = (uint64_t)virt_to_phys(
			jr_privdata->outrings);
	if ((!jr_privdata->paddr_inrings) ||
		(!jr_privdata->paddr_outrings)) {
		JR_TRACE("JR bad queue pointers");
		retstatus = CAAM_FAILURE;
		goto end_init;
	}

	hal_jr_config(jr_privdata->baseaddr, jr_privdata->nbJobs,
					jr_privdata->paddr_inrings,
					jr_privdata->paddr_outrings);

	/*
	 * Prepare the interrupt handler to secure the interrupt even
	 * if the interrupt is not used
	 */
	jr_privdata->it_handler.it      = jr_cfg->it_num;
	jr_privdata->it_handler.flags   = ITRF_TRIGGER_LEVEL;
	jr_privdata->it_handler.handler = caam_jr_irqhandler;
	jr_privdata->it_handler.data    = jr_privdata;

#ifdef CFG_CRYPTO_DRIVER
	itr_add(&jr_privdata->it_handler);
#endif
	hal_jr_enableIT(jr_privdata->baseaddr);

	retstatus = CAAM_NO_ERROR;

end_init:
	if (retstatus != CAAM_NO_ERROR)
		do_jr_free(jr_privdata);

	return retstatus;
}

/**
 * @brief   Request the CAAM JR to halt.
 *          Stop fetching input queue and wait running job
 *          completion.
 *
 * @retval 0    Job Ring is halted
 * @retval (-1) Error occurred
 */
int caam_jr_halt(void)
{
	return hal_jr_halt(jr_privdata->baseaddr);
}

/**
 * @brief   Request the CAAM JR to flush all job running.
 *
 * @retval 0    Job Ring is halted
 * @retval (-1) Error occurred
 */
int caam_jr_flush(void)
{
	return hal_jr_flush(jr_privdata->baseaddr);
}

/**
 * @brief   Resume the CAAM JR processing.
 *
 * @param[in] mode    Power mode to resume from
 */
void caam_jr_resume(uint32_t pm_hint)
{
	enum CAAM_Status retstatus __maybe_unused;

	if (pm_hint == PM_HINT_CONTEXT_STATE) {
#if !(defined(CFG_MX6DL) || defined(CFG_MX6D) || \
		defined(CFG_MX6Q) || defined(CFG_MX6QP))

#ifndef CFG_CRYPTO_DRIVER
		/*
		 * In case the CAAM is not used the JR used to
		 * instantiate the RNG has been released to Non-Secure
		 * hence, need reconfigur the Secure JR and release
		 * it after RNG instantiation
		 */
		hal_jr_setowner(jr_privdata->ctrladdr,
						jr_privdata->jroffset,
						JROWN_ARM_S);

		hal_jr_config(jr_privdata->baseaddr, jr_privdata->nbJobs,
					jr_privdata->paddr_inrings,
					jr_privdata->paddr_outrings);
#endif
		/* Read the current job ring index */
		jr_privdata->inwrite_index = hal_jr_input_index(
				jr_privdata->baseaddr);
		/* Read the current output ring index */
		jr_privdata->outread_index = hal_jr_output_index(
				jr_privdata->baseaddr);

		retstatus = caam_rng_instantiation();
		if (retstatus != CAAM_NO_ERROR)
			panic();
#ifndef CFG_CRYPTO_DRIVER
		hal_jr_setowner(jr_privdata->ctrladdr,
						jr_privdata->jroffset,
						JROWN_ARM_NS);
#endif
#endif
	} else
		hal_jr_resume(jr_privdata->baseaddr);
}

/**
 * @brief   Forces the completion of all CAAM Job to ensure
 *          CAAM is not BUSY.
 *
 * @retval 0    CAAM is no more busy
 * @retval (-1) CAAM is still busy
 */
int caam_jr_complete(void)
{
	int ret;

	ret = hal_jr_flush(jr_privdata->baseaddr);
	if (ret == 0)
		hal_jr_resume(jr_privdata->baseaddr);

	return ret;
}
