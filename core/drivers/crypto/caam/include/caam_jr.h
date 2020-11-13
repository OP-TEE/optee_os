/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Rings module header.
 */
#ifndef __CAAM_JR_H__
#define __CAAM_JR_H__

#include <caam_jr_status.h>
#include <types_ext.h>

/*
 * Job context to enqueue/dequeue
 */
struct caam_jobctx {
	uint32_t *desc;      /* reference to the descriptor */
	uint32_t status;     /* executed job status */
	uint32_t id;         /* Job identifier */
	bool completion;     /* job completion flag */
	void *context;       /* caller job context */
	void (*callback)(struct caam_jobctx *ctx); /* job completion callback */
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
 * The CAAM physical address is decorrelated from the CPU addressing mode.
 * CAAM can manage 32 or 64 bits address depending on its version and the
 * device.
 */
/*
 * Definition of input and output ring object
 */
#ifdef CFG_CAAM_64BIT
struct caam_inring_entry {
	uint64_t desc; /* Physical address of the descriptor */
};

struct caam_outring_entry {
	uint64_t desc;	 /* Physical address of the descriptor */
	uint32_t status; /* Status of the executed job */
} __packed;
#else
struct caam_inring_entry {
	uint32_t desc; /* Physical address of the descriptor */
};

struct caam_outring_entry {
	uint32_t desc;	 /* Physical address of the descriptor */
	uint32_t status; /* Status of the executed job */
} __packed;
#endif /* CFG_CAAM_64BIT */

/*
 * Initialization of the CAAM Job Ring module
 *
 * @jrcfg  Job Ring Configuration
 */
enum caam_status caam_jr_init(struct caam_jrcfg *jrcfg);

/*
 * Cancels a job ID. Remove the job from SW Job array
 *
 * @job_id      Job ID
 */
void caam_jr_cancel(uint32_t job_id);

/*
 * Checks if one of the given job IDs in bit mask format
 * is completed. If none is completed, wait until timeout expires.
 * Endlessly wait if @timeout_ms = UINT_MAX
 *
 * @job_ids     Job IDs Mask
 * @timeout_ms  Timeout in millisecond
 */
enum caam_status caam_jr_dequeue(uint32_t job_ids, unsigned int timeout_ms);

/*
 * Enqueues a job in the Job Ring input queue and either wait until job
 * completion or if job is asynchrnous, returns immediately (if status
 * success, the output parameter job_id is filled with the Job Id pushed)
 *
 * @jobctx  Reference to the job context
 * @job_id  [out] If pointer not NULL, job is asynchronous and parameter is
 *                the Job Id enqueued
 */
enum caam_status caam_jr_enqueue(struct caam_jobctx *jobctx, uint32_t *job_id);

/*
 * Request the CAAM JR to halt.
 * Stop fetching input queue and wait running job completion.
 */
enum caam_status caam_jr_halt(void);

/* Request the CAAM JR to flush all job running. */
enum caam_status caam_jr_flush(void);

/*
 * Resume the CAAM JR processing.
 *
 * @pm_hints  Hint on current power transition
 */
void caam_jr_resume(uint32_t pm_hints);

/* Forces the completion of all CAAM Job to ensure CAAM is not BUSY. */
enum caam_status caam_jr_complete(void);
#endif /* __CAAM_JR_H__ */
