/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016-2018, STMicroelectronics
 */

#ifndef __STM32MP1_BSEC_SVC_H__
#define __STM32MP1_BSEC_SVC_H__

#include <stdint.h>
#include <stm32mp1_smc.h>

#ifdef CFG_STM32_BSEC_SIP
uint32_t bsec_main(uint32_t cmd, uint32_t otp_id, uint32_t in_value,
		   uint32_t *out_value);
#else
static inline uint32_t bsec_main(uint32_t cmd __unused,
				 uint32_t otp_id __unused,
				 uint32_t in_value __unused,
				 uint32_t *out_value __unused)
{
	return STM32_SIP_SVC_FAILED;
}
#endif

#endif /*__STM32MP1_BSEC_SVC_H__*/
