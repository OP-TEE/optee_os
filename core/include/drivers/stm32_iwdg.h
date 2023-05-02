/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2022, STMicroelectronics - All Rights Reserved
 */

#ifndef DRIVERS_STM32_IWDG_H
#define DRIVERS_STM32_IWDG_H

#include <stdbool.h>

/*
 * struct stm32_iwdg_otp_data - Fuses configuration related to an IWDG
 * @hw_enabled - IWDDG instance is enabled by early hardware boot stage
 * @disable_on_stop - IWDG instance freezes when SoC is in STOP mode
 * @disable_on_standby - IWDG instance freezes when SoC is in STANDBY mode
 */
struct stm32_iwdg_otp_data {
	bool hw_enabled;
	bool disable_on_stop;
	bool disable_on_standby;
};

/*
 * Platform shall implement this function for IWDG instance to retrieve its
 * OTP/fuse configuration.
 */
TEE_Result stm32_get_iwdg_otp_config(paddr_t pbase,
				     struct stm32_iwdg_otp_data *otp_data);

/* Refresh all registered IWDG watchdog instance */
void stm32_iwdg_refresh(void);

#endif /*DRIVERS_STM32_IWDG_H*/
