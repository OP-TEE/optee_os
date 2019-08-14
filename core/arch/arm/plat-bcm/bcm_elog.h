/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef BCM_ELOG_H
#define BCM_ELOG_H

#include <mm/core_memprot.h>

/* Error logging signature offset and value */
#define BCM_ELOG_SIG_OFFSET	0x0000
#define BCM_ELOG_SIG_VAL	0x75767971

/* Current logging offset that points to where new logs should be added */
#define BCM_ELOG_OFF_OFFSET	0x0004

/* Current logging length (excluding header) */
#define BCM_ELOG_LEN_OFFSET	0x0008

#define BCM_ELOG_HEADER_LEN	12

/*
 * @base: base address of memory where log is saved
 * @max_size: max size of memory reserved for logging
 */
struct bcm_elog {
	struct io_pa_va base;
	uint32_t max_size;
};

void bcm_elog_init(uintptr_t pa_base, uint32_t size);
void bcm_elog_putchar(char ch);

#endif /* BCM_ELOG_H */
