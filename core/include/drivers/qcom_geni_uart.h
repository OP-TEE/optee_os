/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef __DRIVERS_QCOM_GENI_UART_H
#define __DRIVERS_QCOM_GENI_UART_H

#include <drivers/serial.h>
#include <types_ext.h>

#define GENI_UART_REG_SIZE 0x4000

struct qcom_geni_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void qcom_geni_uart_init(struct qcom_geni_uart_data *pd, paddr_t base);

#endif /* __DRIVERS_QCOM_GENI_UART_H */
