/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef DRIVERS_PLIC_H
#define DRIVERS_PLIC_H

#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <platform_config.h>

void plic_init(paddr_t plic_base_pa);
void plic_hart_init(void);
void plic_it_handle(void);
void plic_dump_state(void);

#endif /*DRIVERS_PLIC_H*/
