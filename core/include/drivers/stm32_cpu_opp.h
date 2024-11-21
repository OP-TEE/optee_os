/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */

#ifndef DRIVERS_STM32_CPU_OPP_H
#define DRIVERS_STM32_CPU_OPP_H

#include <tee_api_types.h>

/* Get the actual number of CPU operating points */
unsigned int stm32_cpu_opp_count(void);

/* Get sustained frequency level */
unsigned int stm32_cpu_opp_sustained_level(void);

/* Get level value identifying CPU operating point @opp_index */
unsigned int stm32_cpu_opp_level(unsigned int opp);

/* Request to switch to CPU operating point related to @level */
TEE_Result stm32_cpu_opp_set_level(unsigned int level);

/* Get level (Freq KHz) related to current CPU operating point */
TEE_Result stm32_cpu_opp_read_level(unsigned int *level);

#endif /*DRIVERS_STM32_CPU_OPP_H*/
