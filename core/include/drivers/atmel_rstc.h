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
void sam_rstc_usb_por(unsigned char id, bool enable);
#else
static inline bool atmel_rstc_available(void)
{
	return false;
}

static inline void atmel_rstc_reset(void) {}
static inline void sam_rstc_usb_por(unsigned char id __unused,
				    bool enable __unused) {}
#endif

#endif /* __DRIVERS_ATMEL_RSTC_H */
