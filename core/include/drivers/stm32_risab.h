/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RISAB_H__
#define __DRIVERS_STM32_RISAB_H__

/*
 * stm32_risab_clear_illegal_access_flags() - Clears flags raised when an
 * illegal access occurs on a memory region
 */
#if defined(CFG_STM32_RISAB)
void stm32_risab_clear_illegal_access_flags(void);
#else /* defined(CFG_STM32_RISAB) */
static inline void stm32_risab_clear_illegal_access_flags(void)
{
}
#endif /* defined(CFG_STM32_RISAB) */

/*
 * stm32_risab_print_erroneous_data() - Prints the data associated to an illegal
 * access occurring on a memory protected by a RISAB : faulty address and
 * firewall attributes of the master causing the illegal access.
 */
#if defined(CFG_STM32_RISAB) && defined(CFG_TEE_CORE_DEBUG)
void stm32_risab_print_erroneous_data(void);
#else /* defined(CFG_STM32_RISAB) && defined(CFG_TEE_CORE_DEBUG) */
static inline void stm32_risab_print_erroneous_data(void)
{
}
#endif /* defined(CFG_STM32_RISAB) && defined(CFG_TEE_CORE_DEBUG) */

#endif /*__DRIVERS_STM32_RISAB_H__*/
