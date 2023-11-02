/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32MP1_SYSCFG_H
#define __DRIVERS_STM32MP1_SYSCFG_H

/* High Speed Low Voltage domains IDs for STM32MP13 variants */
enum stm32mp13_hslv_id {
	SYSCFG_HSLV_IDX_TPIU = 0,
	SYSCFG_HSLV_IDX_QSPI,
	SYSCFG_HSLV_IDX_ETH1,
	SYSCFG_HSLV_IDX_ETH2,
	SYSCFG_HSLV_IDX_SDMMC1,
	SYSCFG_HSLV_IDX_SDMMC2,
	SYSCFG_HSLV_IDX_SPI1,
	SYSCFG_HSLV_IDX_SPI2,
	SYSCFG_HSLV_IDX_SPI3,
	SYSCFG_HSLV_IDX_SPI4,
	SYSCFG_HSLV_IDX_SPI5,
	SYSCFG_HSLV_IDX_LTDC,
	SYSCFG_HSLV_COUNT
};

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

/*
 * Enable or disable High Speed Low Voltage mode of an IO domain
 * @index: HSLV IO domain ID
 * @enable: True to enable IO compensation, false to disable
 */
void stm32mp_set_hslv_state(enum stm32mp13_hslv_id id, bool enable);
#endif /*CFG_STM32MP13*/

/* Enable High Speed Low Voltage mode for domains fixed supplied VDD */
void stm32mp_enable_fixed_vdd_hslv(void);
#endif /*__DRIVERS_STM32MP1_SYSCFG_H*/
