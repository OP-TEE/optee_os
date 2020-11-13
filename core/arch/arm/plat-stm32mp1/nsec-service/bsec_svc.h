/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016-2020, STMicroelectronics
 */

#ifndef __STM32MP1_BSEC_SVC_H__
#define __STM32MP1_BSEC_SVC_H__

#include <kernel/thread.h>
#include <stdint.h>
#include <stm32mp1_smc.h>

#ifdef CFG_STM32_BSEC_SIP
void bsec_main(struct thread_smc_args *args);
#else
static inline void bsec_main(struct thread_smc_args *args)
{
	args->a0 = STM32_SIP_SVC_UNKNOWN_FUNCTION;
}
#endif
#endif /*__STM32MP1_BSEC_SVC_H__*/
