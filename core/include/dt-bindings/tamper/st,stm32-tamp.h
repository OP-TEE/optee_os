/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * Copyright (C) STMicroelectronics 2023-2025 - All Rights Reserved
 * Author: Gatien Chevallier <gatien.chevallier@foss.st.com>
 */

#ifndef _DT_BINDINGS_TAMPER_ST_STM32_TAMP_H_
#define _DT_BINDINGS_TAMPER_ST_STM32_TAMP_H_

/* Internal Tampers */
#define INT_TAMPER_RTC_VOLTAGE_MONITORING	1
#define INT_TAMPER_TEMPERATURE_MONITORING	2
#define INT_TAMPER_LSE_MONITORING		3
#define INT_TAMPER_HSE_MONITORING		4
#define INT_TAMPER_RTC_CALENDAR_OVERFLOW	5
/* Nothing for tampers 6-7 */
#define INT_TAMPER_6				6
#define INT_TAMPER_7				7
#define INT_TAMPER_MONOTONIC_COUNTER		8

/* External Tampers */
#define EXT_TAMPER_1				1
#define EXT_TAMPER_2				2
#define EXT_TAMPER_3				3

/* Tamper mode */
#define TAMPER_CONFIRMED_MODE			1
#define TAMPER_POTENTIAL_MODE			2

#endif /* _DT_BINDINGS_TAMPER_ST_STM32_TAMP_H_ */
