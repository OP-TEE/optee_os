/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Rings module header.
 */
#ifndef __CAAM_JR_H__
#define __CAAM_JR_H__

#include <caam_jr_status.h>

/*
 * Job context to enqueue/dequeue
 */
struct caam_jobctx {
	uint32_t *desc;      /* reference to the descriptor */
	uint32_t status;     /* executed job status */
	uint32_t id;         /* Job identifier */
	bool completion;     /* job completion flag */
	void *context;       /* caller job context */
	void (*callbk)(struct caam_jobctx *ctx); /* job completion callback */
};

/*
 * Job Ring module configuration
 */
struct caam_jrcfg {
	vaddr_t base;    /* CAAM virtual base address */
	paddr_t offset;  /* Job Ring address offset */
	int it_num;      /* Job Ring interrupt number */
	uint8_t nb_jobs; /* Number of Jobs to managed */
};

/*
 * Initialization of the CAAM Job Ring module
 *
 * @jrcfg  Job Ring Configuration
 */
enum CAAM_Status caam_jr_init(struct caam_jrcfg *jrcfg);

/*
 * Cancels a job id. Remove the job from SW Job array
 *
 * @job_id      Job Id
 */
void caam_jr_cancel(uint32_t job_id);

/*
 * Checks if one of the given job ids in bit mask format
 * is complete. If none are complete, wait until timeout expired.
 * Wait infinitively is @timeout_ms = (-1)
 *
 * @job_ids     Job Ids Mask
 * @timeout_ms  Timeout in millisecond
 */
enum CAAM_Status caam_jr_dequeue(uint32_t job_ids, unsigned int timeout_ms);

/*
 * Enqueues a job in the Job Ring input queue and either wait until job
 * completion or if job is asynchrnous, returns immediately (if status
 * success, the output parameter job_id is filled with the Job Id pushed)
 *
 * @jobctx  Reference to the job context
 * @job_id  [out] If pointer not NULL, job is asynchronous and parameter is
 *                the Job Id enqueued
 */
enum CAAM_Status caam_jr_enqueue(struct caam_jobctx *jobctx, uint32_t *job_id);

/*
 * Request the CAAM JR to halt.
 * Stop fetching input queue and wait running job completion.
 */
enum CAAM_Status caam_jr_halt(void);

/* Request the CAAM JR to flush all job running. */
enum CAAM_Status caam_jr_flush(void);

/*
 * Resume the CAAM JR processing.
 *
 * @mode    Power mode to resume from
 */
void caam_jr_resume(uint32_t pm_hints);

/* Forces the completion of all CAAM Job to ensure CAAM is not BUSY. */
enum CAAM_Status caam_jr_complete(void);
#endif /* __CAAM_JR_H__ */
