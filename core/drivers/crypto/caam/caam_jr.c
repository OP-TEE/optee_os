// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Rings manager.
 *         Implementation of functions to enqueue/dequeue CAAM Job Descriptor
 */
#include <caam_common.h>
#include <caam_desc_helper.h>
#include <caam_hal_jr.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_rng.h>
#include <caam_utils_delay.h>
#include <caam_utils_mem.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>

/*
 * Job Free define
 */
#define JR_JOB_FREE	0

/*
 * Caller information context object
 */
struct caller_info {
	struct caam_jobctx *jobctx; /* Caller job context object */
	uint32_t job_id;            /* Current Job ID */
	paddr_t pdesc;              /* Physical address of the descriptor */
};

/*
 * Job Ring module private data
 */
struct jr_privdata {
	vaddr_t baseaddr;        /* Job Ring base address */

	vaddr_t ctrladdr;        /* CAAM virtual base address */
	paddr_t jroffset;        /* Job Ring address offset */
	uint64_t paddr_inrings;  /* CAAM physical addr of input queue */
	uint64_t paddr_outrings; /* CAAM physical addr of output queue */

	uint8_t nb_jobs;         /* Number of Job ring entries managed */

	/* Input Job Ring Variables */
	struct caam_inring_entry *inrings; /* Input JR HW queue */
	unsigned int inlock;          /* Input JR spin lock */
	uint16_t inwrite_index;       /* SW Index - next JR entry free */

	/* Output Job Ring Variables */
	struct caam_outring_entry *outrings; /* Output JR HW queue */
	unsigned int outlock;           /* Output JR spin lock */
	uint16_t outread_index;         /* SW Index - next JR output done */

	/* Caller Information Variables */
	struct caller_info *callers;    /* Job Ring Caller information */
	unsigned int callers_lock;      /* Job Ring Caller spin lock */

	struct itr_handler it_handler;  /* Interrupt handler */
};

/*
 * Job Ring module private data reference
 */
static struct jr_privdata *jr_privdata;

/*
 * Free module resources
 *
 * @jr_priv   Reference to the module private data
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

/*
 * Allocate module resources
 *
 * @privdata  [out] Allocated Job Ring private data
 * @nb_jobs   Number of jobs to manage in the queue
 */
static enum caam_status do_jr_alloc(struct jr_privdata **privdata,
				    uint8_t nb_jobs)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	struct jr_privdata *jr_priv = NULL;

	/* Allocate the Job Ring private data */
	jr_priv = caam_calloc(sizeof(*jr_priv));

	if (!jr_priv) {
		JR_TRACE("Private Data allocation error");
		goto end_alloc;
	}

	/* Setup the number of jobs */
	jr_priv->nb_jobs = nb_jobs;

	/* Allocate the input and output job ring queues */
	jr_priv->inrings =
		caam_calloc_align(nb_jobs * sizeof(struct caam_inring_entry));
	jr_priv->outrings =
		caam_calloc_align(nb_jobs * sizeof(struct caam_outring_entry));

	/* Allocate the callers information */
	jr_priv->callers = caam_calloc(nb_jobs * sizeof(struct caller_info));

	if (!jr_priv->inrings || !jr_priv->outrings || !jr_priv->callers) {
		JR_TRACE("JR resources allocation error");
		goto end_alloc;
	}

	/* Initialize the spin locks */
	jr_priv->inlock = SPINLOCK_UNLOCK;
	jr_priv->outlock = SPINLOCK_UNLOCK;
	jr_priv->callers_lock = SPINLOCK_UNLOCK;

	/* Initialize the queue counter */
	jr_priv->inwrite_index = 0;
	jr_priv->outread_index = 0;

	/*
	 * Ensure that allocated queue initialization is pushed to the physical
	 * memory
	 */
	cache_operation(TEE_CACHEFLUSH, jr_priv->inrings,
			nb_jobs * sizeof(struct caam_inring_entry));
	cache_operation(TEE_CACHEFLUSH, jr_priv->outrings,
			nb_jobs * sizeof(struct caam_outring_entry));

	retstatus = CAAM_NO_ERROR;
end_alloc:
	if (retstatus != CAAM_NO_ERROR)
		do_jr_free(jr_priv);
	else
		*privdata = jr_priv;

	return retstatus;
}

/*
 * Job Ring Interrupt handler
 *
 * @handler  Interrupt Handler structure
 */
static enum itr_return caam_jr_irqhandler(struct itr_handler *handler)
{
	JR_TRACE("Disable the interrupt");
	itr_disable(handler->it);

	/* Send a signal to exit WFE loop */
	sev();

	return ITRR_HANDLED;
}

/*
 * Returns all jobs completed depending on the input @wait_job_ids mask.
 *
 * Dequeues all Jobs completed. Call the job context callback
 * function. Function returns the bit mask of the expected completed job
 * (@wait_job_ids parameter)
 *
 * @wait_job_ids  Expected Jobs to be complete
 */
static uint32_t do_jr_dequeue(uint32_t wait_job_ids)
{
	uint32_t ret_job_id = 0;
	struct caller_info *caller = NULL;
	struct caam_outring_entry *jr_out = NULL;
	struct caam_jobctx *jobctx = NULL;
	uint32_t exceptions = 0;
	bool found = false;
	uint16_t idx_jr = 0;
	uint32_t nb_jobs_done = 0;
	size_t nb_jobs_inv = 0;

	exceptions = cpu_spin_lock_xsave(&jr_privdata->outlock);

	nb_jobs_done = caam_hal_jr_get_nbjob_done(jr_privdata->baseaddr);

	if (nb_jobs_done == 0) {
		cpu_spin_unlock_xrestore(&jr_privdata->outlock, exceptions);
		return ret_job_id;
	}

	/* Ensure that output ring descriptor entries are not in cache */
	if ((jr_privdata->outread_index + nb_jobs_done) >
	    jr_privdata->nb_jobs) {
		/*
		 * Invalidate the whole circular job buffer because some
		 * completed job rings are at the beginning of the buffer
		 */
		jr_out = jr_privdata->outrings;
		nb_jobs_inv = jr_privdata->nb_jobs;
	} else {
		/* Invalidate only the completed job */
		jr_out = &jr_privdata->outrings[jr_privdata->outread_index];
		nb_jobs_inv = nb_jobs_done;
	}

	cache_operation(TEE_CACHEINVALIDATE, jr_out,
			sizeof(struct caam_outring_entry) * nb_jobs_inv);

	for (; nb_jobs_done; nb_jobs_done--) {
		jr_out = &jr_privdata->outrings[jr_privdata->outread_index];

		/*
		 * Lock the caller information array because enqueue is
		 * also touching it
		 */
		cpu_spin_lock(&jr_privdata->callers_lock);
		for (idx_jr = 0, found = false; idx_jr < jr_privdata->nb_jobs;
		     idx_jr++) {
			/*
			 * Search for the caller information corresponding to
			 * the completed JR.
			 * Don't use the outread_index or inwrite_index because
			 * completion can be out of order compared to input
			 * buffer
			 */
			caller = &jr_privdata->callers[idx_jr];
			if (caam_desc_pop(jr_out) == caller->pdesc) {
				jobctx = caller->jobctx;
				jobctx->status = caam_read_jobstatus(jr_out);

				/* Update return Job IDs mask */
				if (caller->job_id & wait_job_ids)
					ret_job_id |= caller->job_id;

				JR_TRACE("JR id=%" PRId32
					 ", context @0x%08" PRIxVA,
					 caller->job_id, (vaddr_t)jobctx);
				/* Clear the Entry Descriptor DMA */
				caller->pdesc = 0;
				caller->jobctx = NULL;
				caller->job_id = JR_JOB_FREE;
				found = true;
				JR_TRACE("Free space #%" PRId16
					 " in the callers array",
					 idx_jr);
				break;
			}
		}
		cpu_spin_unlock(&jr_privdata->callers_lock);

		/*
		 * Remove the JR from the output list even if no
		 * JR caller found
		 */
		caam_hal_jr_del_job(jr_privdata->baseaddr);

		/*
		 * Increment index to next JR output entry taking care that
		 * it is a circular buffer of nb_jobs size.
		 */
		jr_privdata->outread_index++;
		jr_privdata->outread_index %= jr_privdata->nb_jobs;

		if (found && jobctx->callback) {
			/* Finally, execute user's callback */
			jobctx->callback(jobctx);
		}
	}

	cpu_spin_unlock_xrestore(&jr_privdata->outlock, exceptions);

	return ret_job_id;
}

/*
 * Enqueues a new job in the Job Ring input queue. Keep the caller's
 * job context in private array.
 *
 * @jobctx   Caller's job context
 * @job_id   [out] Job ID enqueued
 */
static enum caam_status do_jr_enqueue(struct caam_jobctx *jobctx,
				      uint32_t *job_id)
{
	enum caam_status retstatus = CAAM_BUSY;
	struct caam_inring_entry *cur_inrings = NULL;
	struct caller_info *caller = NULL;
	uint32_t exceptions = 0;
	uint32_t job_mask = 0;
	uint8_t idx_jr = 0;
	bool found = false;

	exceptions = cpu_spin_lock_xsave(&jr_privdata->inlock);

	/*
	 * Stay locked until a job is available
	 * Check if there is an available JR index in the HW
	 */
	while (caam_hal_jr_read_nbslot_available(jr_privdata->baseaddr) == 0) {
		/*
		 * WFE will return thanks to a SEV generated by the
		 * interrupt handler or by a spin_unlock
		 */
		wfe();
	};

	/*
	 * There is a space free in the input ring but it doesn't mean
	 * that the job pushed is completed.
	 * Completion is out of order. Look for a free space in the
	 * caller data to push them and get a job ID for the completion
	 *
	 * Lock the caller information array because dequeue is
	 * also touching it
	 */
	cpu_spin_lock(&jr_privdata->callers_lock);
	for (idx_jr = 0; idx_jr < jr_privdata->nb_jobs; idx_jr++) {
		if (jr_privdata->callers[idx_jr].job_id == JR_JOB_FREE) {
			JR_TRACE("Found a space #%" PRId8
				 " free in the callers array",
				 idx_jr);
			job_mask = 1 << idx_jr;

			/* Store the caller information for the JR completion */
			caller = &jr_privdata->callers[idx_jr];
			caller->job_id = job_mask;
			caller->jobctx = jobctx;
			caller->pdesc = virt_to_phys((void *)jobctx->desc);

			found = true;
			break;
		}
	}
	cpu_spin_unlock(&jr_privdata->callers_lock);

	if (!found) {
		JR_TRACE("Error didn't find a free space in the callers array");
		goto end_enqueue;
	}

	JR_TRACE("Push id=%" PRId16 ", job (0x%08" PRIx32
		 ") context @0x%08" PRIxVA,
		 jr_privdata->inwrite_index, job_mask, (vaddr_t)jobctx);

	cur_inrings = &jr_privdata->inrings[jr_privdata->inwrite_index];

	/* Push the descriptor into the JR HW list */
	caam_desc_push(cur_inrings, caller->pdesc);

	/* Ensure that physical memory is up to date */
	cache_operation(TEE_CACHECLEAN, cur_inrings,
			sizeof(struct caam_inring_entry));

	/*
	 * Increment index to next JR input entry taking care that
	 * it is a circular buffer of nb_jobs size.
	 */
	jr_privdata->inwrite_index++;
	jr_privdata->inwrite_index %= jr_privdata->nb_jobs;

	/* Ensure that input descriptor is pushed in physical memory */
	cache_operation(TEE_CACHECLEAN, jobctx->desc,
			DESC_SZBYTES(caam_desc_get_len(jobctx->desc)));

	/* Inform HW that a new JR is available */
	caam_hal_jr_add_newjob(jr_privdata->baseaddr);

	*job_id = job_mask;
	retstatus = CAAM_NO_ERROR;

end_enqueue:
	cpu_spin_unlock_xrestore(&jr_privdata->inlock, exceptions);

	return retstatus;
}

/*
 * Synchronous job completion callback
 *
 * @jobctx   Job context
 */
static void job_done(struct caam_jobctx *jobctx)
{
	jobctx->completion = true;
}

void caam_jr_cancel(uint32_t job_id)
{
	unsigned int idx = 0;

	cpu_spin_lock(&jr_privdata->callers_lock);

	JR_TRACE("Job cancel 0x%" PRIx32, job_id);
	for (idx = 0; idx < jr_privdata->nb_jobs; idx++) {
		/*
		 * Search for the caller information corresponding to
		 * the job_id mask.
		 */
		if (jr_privdata->callers[idx].job_id == job_id) {
			/* Clear the Entry Descriptor */
			jr_privdata->callers[idx].pdesc = 0;
			jr_privdata->callers[idx].jobctx = NULL;
			jr_privdata->callers[idx].job_id = JR_JOB_FREE;
			return;
		}
	}

	cpu_spin_unlock(&jr_privdata->callers_lock);
}

enum caam_status caam_jr_dequeue(uint32_t job_ids, unsigned int timeout_ms)
{
	uint32_t job_complete = 0;
	uint32_t nb_loop = 0;
	bool infinite = false;
	bool it_active = false;

	if (timeout_ms == UINT_MAX)
		infinite = true;
	else
		nb_loop = timeout_ms * 100;

	do {
		/* Call the do_jr_dequeue function to dequeue the jobs */
		job_complete = do_jr_dequeue(job_ids);

		/* Check if new job has been submitted and acknowledge it */
		it_active = caam_hal_jr_check_ack_itr(jr_privdata->baseaddr);

		if (job_complete & job_ids)
			return CAAM_NO_ERROR;

		/* Check if JR interrupt otherwise wait a bit */
		if (!it_active)
			caam_udelay(10);
	} while (infinite || (nb_loop--));

	return CAAM_TIMEOUT;
}

enum caam_status caam_jr_enqueue(struct caam_jobctx *jobctx, uint32_t *job_id)
{
	enum caam_status retstatus = CAAM_FAILURE;
	__maybe_unused int timeout  = 10; /* Nb loops to pool job completion */

	if (!jobctx)
		return CAAM_BAD_PARAM;

	JR_DUMPDESC(jobctx->desc);

	if (!jobctx->callback && job_id) {
		JR_TRACE("Job Callback not defined whereas asynchronous");
		return CAAM_BAD_PARAM;
	}

	if (jobctx->callback && !job_id) {
		JR_TRACE("Job Id not defined whereas asynchronous");
		return CAAM_BAD_PARAM;
	}

	jobctx->completion = false;
	jobctx->status = 0;

	/*
	 * If parameter job_id is NULL, the job is synchronous, hence use
	 * the local job_done callback function
	 */
	if (!jobctx->callback && !job_id) {
		jobctx->callback = job_done;
		jobctx->context = jobctx;
	}

	retstatus = do_jr_enqueue(jobctx, &jobctx->id);

	if (retstatus != CAAM_NO_ERROR) {
		JR_TRACE("enqueue job error 0x%08x", retstatus);
		return retstatus;
	}

	/*
	 * If parameter job_id is defined, the job is asynchronous, so
	 * returns with setting the job_id value
	 */
	if (job_id) {
		*job_id = jobctx->id;
		return CAAM_PENDING;
	}

#ifdef TIMEOUT_COMPLETION
	/*
	 * Job is synchronous wait until job completion or timeout
	 */
	while (!jobctx->completion && timeout--)
		caam_jr_dequeue(jobctx->id, 100);

	if (timeout <= 0) {
		/* Job timeout, cancel it and return in error */
		caam_jr_cancel(jobctx->id);
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
	 * so the timeout is not precise
	 */
	while (!jobctx->completion)
		caam_jr_dequeue(jobctx->id, 100);

	if (JRSTA_SRC_GET(jobctx->status) != JRSTA_SRC(NONE))
		retstatus = CAAM_JOB_STATUS;
	else
		retstatus = CAAM_NO_ERROR;
#endif

	/* Erase local callback function */
	jobctx->callback = NULL;

	return retstatus;
}

enum caam_status caam_jr_init(struct caam_jrcfg *jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;

	JR_TRACE("Initialization");

	/* Allocate the Job Ring resources */
	retstatus = do_jr_alloc(&jr_privdata, jrcfg->nb_jobs);
	if (retstatus != CAAM_NO_ERROR)
		goto end_init;

	jr_privdata->ctrladdr = jrcfg->base;
	jr_privdata->jroffset = jrcfg->offset;

	retstatus =
		caam_hal_jr_setowner(jrcfg->base, jrcfg->offset, JROWN_ARM_S);
	JR_TRACE("JR setowner returned 0x%x", retstatus);

	if (retstatus != CAAM_NO_ERROR)
		goto end_init;

	jr_privdata->baseaddr = jrcfg->base + jrcfg->offset;
	retstatus = caam_hal_jr_reset(jr_privdata->baseaddr);
	if (retstatus != CAAM_NO_ERROR)
		goto end_init;

	/*
	 * Get the physical address of the Input/Output queue
	 * The HW configuration is 64 bits registers regardless
	 * the CAAM or CPU addressing mode.
	 */
	jr_privdata->paddr_inrings = virt_to_phys(jr_privdata->inrings);
	jr_privdata->paddr_outrings = virt_to_phys(jr_privdata->outrings);
	if (!jr_privdata->paddr_inrings || !jr_privdata->paddr_outrings) {
		JR_TRACE("JR bad queue pointers");
		retstatus = CAAM_FAILURE;
		goto end_init;
	}

	caam_hal_jr_config(jr_privdata->baseaddr, jr_privdata->nb_jobs,
			   jr_privdata->paddr_inrings,
			   jr_privdata->paddr_outrings);

	/*
	 * Prepare the interrupt handler to secure the interrupt even
	 * if the interrupt is not used
	 */
	jr_privdata->it_handler.it = jrcfg->it_num;
	jr_privdata->it_handler.flags = ITRF_TRIGGER_LEVEL;
	jr_privdata->it_handler.handler = caam_jr_irqhandler;
	jr_privdata->it_handler.data = jr_privdata;

#if defined(CFG_NXP_CAAM_RUNTIME_JR) && defined(CFG_CAAM_ITR)
	itr_add(&jr_privdata->it_handler);
#endif
	caam_hal_jr_enable_itr(jr_privdata->baseaddr);

	retstatus = CAAM_NO_ERROR;

end_init:
	if (retstatus != CAAM_NO_ERROR)
		do_jr_free(jr_privdata);

	return retstatus;
}

enum caam_status caam_jr_halt(void)
{
	enum caam_status retstatus = CAAM_FAILURE;
	__maybe_unused uint32_t job_complete = 0;

	retstatus = caam_hal_jr_halt(jr_privdata->baseaddr);

	/*
	 * All jobs in the input queue have been done, call the
	 * dequeue function to complete them.
	 */
	job_complete = do_jr_dequeue(UINT32_MAX);
	JR_TRACE("Completion of jobs mask 0x%" PRIx32, job_complete);

	return retstatus;
}

enum caam_status caam_jr_flush(void)
{
	enum caam_status retstatus = CAAM_FAILURE;
	__maybe_unused uint32_t job_complete = 0;

	retstatus = caam_hal_jr_flush(jr_privdata->baseaddr);

	/*
	 * All jobs in the input queue have been done, call the
	 * dequeue function to complete them.
	 */
	job_complete = do_jr_dequeue(UINT32_MAX);
	JR_TRACE("Completion of jobs mask 0x%" PRIx32, job_complete);

	return retstatus;
}

void caam_jr_resume(uint32_t pm_hint)
{
	if (pm_hint == PM_HINT_CONTEXT_STATE) {
#ifndef CFG_NXP_CAAM_RUNTIME_JR
		/*
		 * In case the CAAM is not used the JR used to
		 * instantiate the RNG has been released to Non-Secure
		 * hence, need reconfigure the Secure JR and release
		 * it after RNG instantiation
		 */
		caam_hal_jr_setowner(jr_privdata->ctrladdr,
				     jr_privdata->jroffset, JROWN_ARM_S);

		caam_hal_jr_config(jr_privdata->baseaddr, jr_privdata->nb_jobs,
				   jr_privdata->paddr_inrings,
				   jr_privdata->paddr_outrings);
#endif /* CFG_NXP_CAAM_RUNTIME_JR */

		/* Read the current job ring index */
		jr_privdata->inwrite_index =
			caam_hal_jr_input_index(jr_privdata->baseaddr);
		/* Read the current output ring index */
		jr_privdata->outread_index =
			caam_hal_jr_output_index(jr_privdata->baseaddr);

		if (caam_rng_instantiation() != CAAM_NO_ERROR)
			panic();

#ifndef CFG_NXP_CAAM_RUNTIME_JR
		caam_hal_jr_setowner(jr_privdata->ctrladdr,
				     jr_privdata->jroffset, JROWN_ARM_NS);
#endif /* CFG_NXP_CAAM_RUNTIME_JR */
	} else {
		caam_hal_jr_resume(jr_privdata->baseaddr);
	}
}

enum caam_status caam_jr_complete(void)
{
	enum caam_status ret = CAAM_BUSY;

	ret = caam_hal_jr_flush(jr_privdata->baseaddr);
	if (ret == CAAM_NO_ERROR)
		caam_hal_jr_resume(jr_privdata->baseaddr);

	return ret;
}
