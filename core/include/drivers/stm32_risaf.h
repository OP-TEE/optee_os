/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RISAF_H__
#define __DRIVERS_STM32_RISAF_H__

/*
 * stm32_risaf_clear_illegal_access_flags() - Clears flags raised when an
 * illegal access occurs on a memory region
 */
void stm32_risaf_clear_illegal_access_flags(void);

/*
 * stm32_risaf_print_erroneous_data() - Prints the data associated to an illegal
 * access occurring on a memory protected by a RISAF : faulty address and
 * firewall attributes of the master causing the illegal access. This function
 * is stubbed when CFG_TEE_CORE_DEBUG is disabled.
 */
void stm32_risaf_print_erroneous_data(void);

#endif /*__DRIVERS_STM32_RISAF_H__*/
