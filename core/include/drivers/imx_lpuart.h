/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */
#ifndef IMX_LPUART_H
#define IMX_LPUART_H

#include <types_ext.h>
#include <drivers/serial.h>

struct imx_lpuart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void imx_lpuart_init(struct imx_lpuart_data *pd, paddr_t base);

#endif /* IMX_LPUART_H */
