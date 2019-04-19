/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_jr.h
 *
 * @brief   CAAM Job Rings module header.
 */
#ifndef __CAAM_JR_H__
#define __CAAM_JR_H__

/* Local includes */
#include "jr_status.h"

/**
 * @brief   Job context to enqueue/dequeue
 *
 */
struct jr_jobctx {
	descPointer_t desc;       ///< reference to the descriptor
	descStatus_t  status;     ///< executed job status
	uint32_t      jobId;
	bool          completion; ///< job completion flag
	void          *context;   ///< caller job context
	void (*callbk)(struct jr_jobctx *jobctx); ///< job completion callback
};

/**
 * @brief   Job Ring module configuration
 *
 */
struct jr_cfg {
	vaddr_t base;      ///< CAAM virtual base address
	paddr_t offset;    ///< Job Ring address offset
	int     it_num;    ///< Job Ring interrupt number
	uint8_t nb_jobs;   ///< Number of Jobs to managed
};

/**
 * @brief   Initialization of the CAAM Job Ring module
 *
 * @param[in] jr_cfg  Job Ring Configuration
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_jr_init(struct jr_cfg *jr_cfg);

/**
 * @brief   Cancels a job id. Remove the job from SW Job array
 *
 * @param[in] jobId      Job Id
 *
 */
void caam_jr_cancel(uint32_t jobId);

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
enum CAAM_Status caam_jr_dequeue(uint32_t jobIds, uint32_t timeout_ms);

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
 */
enum CAAM_Status caam_jr_enqueue(struct jr_jobctx *jobctx, uint32_t *jobId);

/**
 * @brief   Request the CAAM JR to halt.
 *          Stop fetching input queue and wait running job
 *          completion.
 *
 * @retval 0    Job Ring is halted
 * @retval (-1) Error occurred
 */
int caam_jr_halt(void);

/**
 * @brief   Request the CAAM JR to flush input queue.
 *
 * @retval 0    Job Ring is halted
 * @retval (-1) Error occurred
 */
int caam_jr_flush(void);

/**
 * @brief   Resume the CAAM JR processing.
 *
 * @param[in] mode    Power mode to resume from
 */
void caam_jr_resume(uint32_t pm_hints);

/**
 * @brief   Forces the completion of all CAAM Job to ensure
 *          CAAM is not BUSY.
 *
 * @retval 0    CAAM is no more busy
 * @retval (-1) CAAM is still busy
 */
int caam_jr_complete(void);
#endif /* __CAAM_JR_H__ */

