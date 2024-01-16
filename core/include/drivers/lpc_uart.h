/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, HiSilicon Limited
 */

#ifndef __DRIVERS_LPC_UART_H
#define __DRIVERS_LPC_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

#define UART_SEND_LOOP_MAX	1000000
#define UART_THR	0x00
#define UART_LSR	0x05

#define UART_USR_BUS	0x01

#define LPC_BASE	0x201190000
#define LPC_SIZE	0x1000000

#define LPC_START_REG_OFFSET           (0x00)
#define LPC_OP_STATUS_REG_OFFSET       (0x04)
#define LPC_IRQ_ST_REG_OFFSET          (0x08)
#define LPC_OP_LEN_REG_OFFSET          (0x10)
#define LPC_CMD_REG_OFFSET             (0x14)
#define LPC_FWH_ID_MSIZE_REG_OFFSET    (0x18)
#define LPC_ADDR_REG_OFFSET            (0x20)
#define LPC_WDATA_REG_OFFSET           (0x24)
#define LPC_RDATA_REG_OFFSET           (0x28)
#define LPC_LONG_CNT_REG_OFFSET        (0x30)
#define LPC_TX_FIFO_ST_REG_OFFSET      (0x50)
#define LPC_RX_FIFO_ST_REG_OFFSET      (0x54)
#define LPC_TIME_OUT_REG_OFFSET        (0x58)
#define LPC_SIRQ_CTRL0_REG_OFFSET      (0x80)
#define LPC_SIRQ_CTRL1_REG_OFFSET      (0x84)
#define LPC_SIRQ_INT_REG_OFFSET        (0x90)
#define LPC_SIRQ_INT_MASK_REG_OFFSET   (0x94)
#define LPC_SIRQ_STAT_REG_OFFSET       (0xa0)

#define LPC_SINGLE_READ		(0x8)
#define LPC_SINGLE_WRITE	(0x9)
#define LPC_IRQ_ST_ON		(0x2)
#define LPC_RADTA_LEN		(0x40)

struct lpc_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void lpc_uart_init(struct lpc_uart_data *pd, paddr_t base,
		   uint32_t uart_clk, uint32_t baud_rate);

#endif /* __DRIVERS_LPC_UART_H */
