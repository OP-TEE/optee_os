/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015 Atmel Corporation,
 *                    Nicolas Ferre <nicolas.ferre@atmel.com>
 * Copyright (c) 2021, Microchip
 */

#ifndef __DRIVERS_ATMEL_SHDWC_H
#define __DRIVERS_ATMEL_SHDWC_H

#include <compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <util.h>

/* Shut Down Control Register */
#define AT91_SHDW_CR		0x00
/* Shut Down command */
#define AT91_SHDW_SHDW		BIT(0)
/* KEY Password */
#define AT91_SHDW_KEY		SHIFT_U32(0xa5UL, 24)

/* Shut Down Mode Register */
#define AT91_SHDW_MR		0x04
#define AT91_SHDW_WKUPDBC_SHIFT	24
#define AT91_SHDW_WKUPDBC_MASK	GENMASK_32(26, 24)
#define AT91_SHDW_WKUPDBC(x)	(SHIFT_U32((x), AT91_SHDW_WKUPDBC_SHIFT) & \
				 AT91_SHDW_WKUPDBC_MASK)
#define AT91_SHDW_RTCWKEN	BIT32(17)

/* Shut Down Status Register */
#define AT91_SHDW_SR		0x08
#define AT91_SHDW_WKUPIS_SHIFT	16
#define AT91_SHDW_WKUPIS_MASK	GENMASK_32(31, 16)
#define AT91_SHDW_WKUPIS(x)	(BIT32((x) + AT91_SHDW_WKUPIS_SHIFT))

/* Shutdown Wake-up Inputs Register */
#define AT91_SHDW_WUIR		0x0c
#define AT91_SHDW_WKUPEN_MASK	GENMASK_32(15, 0)
#define AT91_SHDW_WKUPEN(x)	(BIT32(x) & AT91_SHDW_WKUPEN_MASK)
#define AT91_SHDW_WKUPT_SHIFT	16
#define AT91_SHDW_WKUPT_MASK	GENMASK_32(31, 16)
#define AT91_SHDW_WKUPT(x)	(BIT32((x) + AT91_SHDW_WKUPT_SHIFT))

#ifndef __ASSEMBLER__
#if defined(CFG_ATMEL_SHDWC)

void __atmel_shdwc_shutdown(uint32_t mpddrc_base, uint32_t shdwc_base,
			    uint32_t pmc_base);

bool atmel_shdwc_available(void);

void __noreturn atmel_shdwc_shutdown(void);
#else
static inline bool atmel_shdwc_available(void)
{
	return false;
}

static inline void atmel_shdwc_shutdown(void) {}
#endif /* defined(CFG_ATMEL_SHDWC) */
#endif /* __ASSEMBLER__*/

#endif /* __DRIVERS_ATMEL_SHDWC_H */
