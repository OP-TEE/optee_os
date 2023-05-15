/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */
#ifndef STIH_ASC_H
#define STIH_ASC_H

#include <drivers/serial.h>
#include <types_ext.h>

#define STIH_ASC_REG_SIZE	0x1000

struct stih_asc_pd {
	struct io_pa_va base;
	struct serial_chip chip;
};

void stih_asc_init(struct stih_asc_pd *pb, vaddr_t base);

#endif /* STIH_ASC_H */

