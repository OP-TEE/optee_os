/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * CAAM driver common include file.
 */

#ifndef __CAAM_COMMON_H__
#define __CAAM_COMMON_H__

#include <caam_desc_helper.h>
#include <caam_status.h>
#include <caam_trace.h>
#include <caam_types.h>

/*
 * Definition of the number of CAAM Jobs to manage in JR queues
 */
#if defined(CFG_NB_JOBS_QUEUE)
#define NB_JOBS_QUEUE	CFG_NB_JOBS_QUEUE
#else
#define NB_JOBS_QUEUE 10
#endif

/*
 * Flag Job Ring Owner is Secure
 */
#define JROWNER_SECURE 0x10

/*
 * Job Ring Owner. Enumerate Id (expect the Secure Flag) correspond
 * to the HW ID.
 */
#if !defined(CFG_MX7ULP)
enum caam_jr_owner {
	JROWN_ARM_NS = 0x1,                  /* Non-Secure ARM */
	JROWN_ARM_S  = JROWNER_SECURE | 0x1, /* Secure ARM */
};
#else
enum caam_jr_owner {
	JROWN_ARM_NS = 0x4,                  /* Non-Secure ARM */
	JROWN_ARM_S = JROWNER_SECURE | 0x4,  /* Secure ARM */
};

#endif /* CFG_MX7ULP */

#endif /* __CAAM_COMMON_H__ */
