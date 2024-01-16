/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-3-Clause) */
/*
 * Copyright (C) STMicroelectronics 2023 - All Rights Reserved
 */

#ifndef _DT_BINDINGS_GPIO_STM32MP_GPIO_H
#define _DT_BINDINGS_GPIO_STM32MP_GPIO_H

#include <dt-bindings/gpio/gpio.h>

/* Macro to define the security for GPIO */
#ifdef __ASSEMBLER__
#define TZPROT(id)	(1 << (id))
#else
#define TZPROT(id)	(UINT32_C(1) << (id))
#endif

#endif
