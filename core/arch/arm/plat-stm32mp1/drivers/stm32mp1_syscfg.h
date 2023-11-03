/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32MP1_SYSCFG_H
#define __DRIVERS_STM32MP1_SYSCFG_H

/* IO compensation domains IDs for STM32MP13 variants */
enum stm32mp13_vddsd_comp_id {
	SYSCFG_IO_COMP_IDX_SD1,
	SYSCFG_IO_COMP_IDX_SD2,
	SYSCFG_IO_COMP_COUNT
};

#ifdef CFG_STM32MP13
/*
 * Enable or disable IO compensation for a VDDSD IO domains
 * @id: VDDSD domain ID
 * @enable: True to enable IO compensation, false to disable
 */
void stm32mp_set_vddsd_comp_state(enum stm32mp13_vddsd_comp_id id, bool enable);
#endif /*CFG_STM32MP13*/
#endif /*__DRIVERS_STM32MP1_SYSCFG_H*/
