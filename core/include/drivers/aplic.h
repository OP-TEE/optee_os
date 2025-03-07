/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 Beijing Institute of Open Source Chip (BOSC)
 */

#ifndef __DRIVERS_APLIC_H
#define __DRIVERS_APLIC_H

#include <types_ext.h>

/*
 * The aplic_init() function initializes the struct aplic_data which
 * is then used by other functions. This function also initializes
 * the APLIC and should only be called from the primary boot hart.
 */
void aplic_init(paddr_t aplic_base_pa);

/*
 * Does per-hart specific APLIC initialization, should be called by all
 * secondary harts when booting.
 */
void aplic_init_per_hart(void);

/* Handle external interrupts */
void aplic_it_handle(void);

/* Print APLIC state to console */
void aplic_dump_state(void);

#endif /*__DRIVERS_APLIC_H*/
