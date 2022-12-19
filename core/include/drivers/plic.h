/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef DRIVERS_PLIC_H
#define DRIVERS_PLIC_H

#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <platform_config.h>

struct plic_data {
	vaddr_t plic_base;
	size_t max_it;
	struct itr_chip chip;
};

void plic_init(struct plic_data *pd, paddr_t plic_base_pa);
void plic_init_base_addr(struct plic_data *pd, paddr_t plic_base_pa);
void plic_hart_init(struct plic_data *pd);
void plic_it_handle(struct plic_data *pd);
void plic_dump_state(struct plic_data *pd);

#endif /*DRIVERS_PLIC_H*/
