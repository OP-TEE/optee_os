/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */

#ifndef AT91_PM_H
#define AT91_PM_H

#define	AT91_PM_STANDBY		0x00
#define AT91_PM_ULP0		0x01
#define AT91_PM_ULP0_FAST	0x02
#define AT91_PM_ULP1		0x03
#define	AT91_PM_BACKUP		0x04

#ifndef __ASSEMBLER__

#include <kernel/thread.h>
#include <sm/sm.h>
#include <tee_api_types.h>
#include <types_ext.h>

struct at91_pm_data {
	vaddr_t shdwc;
	vaddr_t securam;
	vaddr_t secumod;
	vaddr_t sfrbu;
	vaddr_t pmc;
	vaddr_t ramc;
	unsigned int mode;
	const void *fdt;
};

void at91_pm_suspend_in_sram(struct at91_pm_data *pm_data);
void at91_pm_cpu_resume(void);
extern uint32_t at91_pm_suspend_in_sram_sz;

void at91_pm_resume(struct at91_pm_data *pm_data);

#endif /* __ASSEMBLER__ */

#endif /* AT91_PM_H */
