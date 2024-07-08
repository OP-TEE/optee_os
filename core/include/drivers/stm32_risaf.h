/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RISAF_H__
#define __DRIVERS_STM32_RISAF_H__

#include <tee_api_types.h>
#include <types_ext.h>

TEE_Result stm32_risaf_reconfigure(paddr_t base);

void stm32_risaf_clear_illegal_access_flags(void);

#ifdef CFG_TEE_CORE_DEBUG
void stm32_risaf_dump_erroneous_data(void);
#else /* CFG_TEE_CORE_DEBUG */
static inline void stm32_risaf_dump_erroneous_data(void)
{
}
#endif /* CFG_TEE_CORE_DEBUG */

#endif /*__DRIVERS_STM32_RISAF_H__*/
