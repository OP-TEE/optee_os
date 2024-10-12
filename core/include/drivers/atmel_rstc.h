/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */
#ifndef __DRIVERS_ATMEL_RSTC_H
#define __DRIVERS_ATMEL_RSTC_H

#include <compiler.h>
#include <drivers/rstctrl.h>
#include <stdbool.h>
#include <util.h>

#define RESET_ID_MASK		GENMASK_32(8, 5)
#define RESET_ID_SHIFT		U(5)
#define RESET_BIT_POS_MASK	GENMASK_32(4, 0)
#define RESET_OFFSET(id)	(((id) & RESET_ID_MASK) >> RESET_ID_SHIFT)
#define RESET_BIT_POS(id)	((id) & RESET_BIT_POS_MASK)

#if defined(CFG_ATMEL_RSTC)
bool atmel_rstc_available(void);

void __noreturn atmel_rstc_reset(void);
void sam_rstc_usb_por(unsigned char id, bool enable);
struct rstctrl *sam_get_rstctrl(unsigned int reset_id);
#else
static inline bool atmel_rstc_available(void)
{
	return false;
}

static inline void atmel_rstc_reset(void) {}
static inline void sam_rstc_usb_por(unsigned char id __unused,
				    bool enable __unused) {}
static inline struct rstctrl *sam_get_rstctrl(unsigned int reset_id __unused)
{
	return NULL;
}
#endif

#endif /* __DRIVERS_ATMEL_RSTC_H */
