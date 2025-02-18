/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2025, STMicroelectronics
 */
#ifndef __DRIVERS_STM32_SERC_H__
#define __DRIVERS_STM32_SERC_H__

/* Helper to print and handle SERC ILACs */
#ifdef CFG_STM32_SERC
void stm32_serc_handle_ilac(void);
#else /* CFG_STM32_SERC */
static inline void stm32_serc_handle_ilac(void) { };
#endif /* CFG_STM32_SERC */

#endif /* __DRIVERS_STM32_SERC_H__ */
