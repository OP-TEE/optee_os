/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#ifndef __KERNEL_DEFERRED_WORK_H
#define __KERNEL_DEFERRED_WORK_H

#include <tee_api_types.h>

#if defined(CFG_DEFERRED_WORK)
/**
 * deferred_work_add() - put a new job in the queue of pending jobs.
 *
 * @name: string with a name of a new job.
 *        The string length is maximum 32 bytes, including '\0'.
 * @work: pointer to a function which will be executed, when
 *        the tee-supplicant will start.
 *        The work has to return 'TEE_SUCCESS', on success case.
 * @data: pointer to data for @work function.
 *
 * Returns 'TEE_SUCCESS' on success. It means the work was added to
 * the queue successfully.
 */
TEE_Result deferred_work_add(const char *name, TEE_Result (*work)(void *data),
			     void *data);

/**
 * deferred_work_do_all() - execute all pending works in the queue.
 *
 * This function will be called in dw PTA (see 'core/pta/dw.c')
 * by the tee-supplicant, when it will be run.
 *
 * Returns 'TEE_SUCCESS' after execution of all pending works.
 */
TEE_Result deferred_work_do_all(void);

#else
static inline TEE_Result deferred_work_add(const char *name __unused,
					   TEE_Result (*work)(void *data)
						   __unused,
					   void *data __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result deferred_work_do_all(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_DEFERRED_WORK */

#endif /* __KERNEL_DEFERRED_WORK_H */
