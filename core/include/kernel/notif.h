/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#ifndef __KERNEL_NOTIF_H
#define __KERNEL_NOTIF_H

#include <compiler.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define NOTIF_SYNC_VALUE_BASE		0

#define NOTIF_VALUE_MAX			(NOTIF_SYNC_VALUE_BASE + \
					 CFG_NUM_THREADS)

/*
 * Wait in normal world for a value to be sent by notif_send_sync()
 */
TEE_Result notif_wait(uint32_t value);

/*
 * Send a value
 */
TEE_Result notif_send_sync(uint32_t value);

#endif /*__KERNEL_NOTIF_H*/
