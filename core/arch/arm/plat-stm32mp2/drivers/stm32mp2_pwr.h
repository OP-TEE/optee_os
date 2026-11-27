/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, STMicroelectronics
 */

#ifndef __STM32MP2_PWR_H
#define __STM32MP2_PWR_H

enum pwr_monitoring {
	PWR_MON_V08CAP_TEMP,
	PWR_MON_VCORE,
	PWR_MON_VCPU,
};

vaddr_t stm32_pwr_base(void);

#endif /*__STM32MP2_PWR_H*/
