/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */
#ifndef __DRIVERS_ATMEL_RSTC_H
#define __DRIVERS_ATMEL_RSTC_H

#include <compiler.h>
#include <stdbool.h>

#if defined(CFG_ATMEL_RSTC)
bool atmel_rstc_available(void);

void __noreturn atmel_rstc_reset(void);
#else
static inline bool atmel_rstc_available(void)
{
	return false;
}

static inline void atmel_rstc_reset(void) {}
#endif

#endif /* __DRIVERS_ATMEL_RSTC_H */
