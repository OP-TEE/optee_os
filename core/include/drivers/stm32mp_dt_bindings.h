/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */
#ifndef __DRIVERS_STM32MP_DT_BINDINGS_H
#define __DRIVERS_STM32MP_DT_BINDINGS_H

#ifdef CFG_STM32MP13
#include <dt-bindings/clock/stm32mp13-clks.h>
#include <dt-bindings/clock/stm32mp13-clksrc.h>
#include <dt-bindings/firewall/stm32mp13-etzpc.h>
#include <dt-bindings/firewall/stm32mp13-tzc400.h>
#include <dt-bindings/regulator/st,stm32mp13-regulator.h>
#include <dt-bindings/reset/stm32mp13-resets.h>
#endif

#ifdef CFG_STM32MP15
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <dt-bindings/firewall/stm32mp15-etzpc.h>
#include <dt-bindings/firewall/stm32mp15-tzc400.h>
#include <dt-bindings/regulator/st,stm32mp15-regulator.h>
#include <dt-bindings/reset/stm32mp1-resets.h>
#endif

#ifdef CFG_STM32MP25
#include <dt-bindings/clock/st,stm32mp25-rcc.h>
#include <dt-bindings/clock/stm32mp25-clksrc.h>
#include <dt-bindings/firewall/stm32mp25-rif.h>
#include <dt-bindings/firewall/stm32mp25-rifsc.h>
#include <dt-bindings/firewall/stm32mp25-risaf.h>
#include <dt-bindings/reset/st,stm32mp25-rcc.h>
#endif

#endif /* __DRIVERS_STM32MP_DT_BINDINGS_H */
