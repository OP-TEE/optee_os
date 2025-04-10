// SPDX-License-Identifier: BSD-2-Clause
/*
 * Qualcomm GENI serial engine UART driver
 *
 * Copyright (c) 2021 Dzmitry Sankouski <dsankouski@gmail.com>
 * Copyright (c) 2024, Linaro Limited
 *
 * Based on U-Boot driver
 */

#include <compiler.h>
#include <console.h>
#include <drivers/geni_uart.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <util.h>

#define USEC_PER_SEC	1000000L

/* Registers*/
#define GENI_FORCE_DEFAULT_REG	0x20
#define GENI_SER_M_CLK_CFG	0x48
#define GENI_SER_S_CLK_CFG	0x4C
#define SE_HW_PARAM_0	0xE24
#define SE_GENI_STATUS	0x40
#define SE_GENI_S_CMD0	0x630
#define SE_GENI_S_CMD_CTRL_REG	0x634
#define SE_GENI_S_IRQ_CLEAR	0x648
#define SE_GENI_S_IRQ_STATUS	0x640
#define SE_GENI_S_IRQ_EN	0x644
#define SE_GENI_M_CMD0	0x600
#define SE_GENI_M_CMD_CTRL_REG	0x604
#define SE_GENI_M_IRQ_CLEAR	0x618
#define SE_GENI_M_IRQ_STATUS	0x610
#define SE_GENI_M_IRQ_EN	0x614
#define SE_GENI_TX_FIFOn	0x700
#define SE_GENI_RX_FIFOn	0x780
#define SE_GENI_TX_FIFO_STATUS	0x800
#define SE_GENI_RX_FIFO_STATUS	0x804
#define SE_GENI_TX_WATERMARK_REG	0x80C
#define SE_GENI_TX_PACKING_CFG0	0x260
#define SE_GENI_TX_PACKING_CFG1	0x264
#define SE_GENI_RX_PACKING_CFG0	0x284
#define SE_GENI_RX_PACKING_CFG1	0x288
#define SE_UART_RX_STALE_CNT	0x294
#define SE_UART_TX_TRANS_LEN	0x270
#define SE_UART_TX_STOP_BIT_LEN	0x26c
#define SE_UART_TX_WORD_LEN	0x268
#define SE_UART_RX_WORD_LEN	0x28c
#define SE_UART_TX_TRANS_CFG	0x25c
#define SE_UART_TX_PARITY_CFG	0x2a4
#define SE_UART_RX_TRANS_CFG	0x280
#define SE_UART_RX_PARITY_CFG	0x2a8

#define M_TX_FIFO_WATERMARK_EN	(BIT(30))
#define DEF_TX_WM	2
/* GENI_FORCE_DEFAULT_REG fields */
#define FORCE_DEFAULT	(BIT(0))

#define S_CMD_ABORT_EN	(BIT(5))

#define UART_START_READ	0x1

/* GENI_M_CMD_CTRL_REG */
#define M_GENI_CMD_CANCEL	(BIT(2))
#define M_GENI_CMD_ABORT	(BIT(1))
#define M_GENI_DISABLE	(BIT(0))

#define M_CMD_ABORT_EN	(BIT(5))
#define M_CMD_DONE_EN	(BIT(0))
#define M_CMD_DONE_DISABLE_MASK	(~M_CMD_DONE_EN)

#define S_GENI_CMD_ABORT	(BIT(1))

/* GENI_S_CMD0 fields */
#define S_OPCODE_MSK	(GENMASK_32(31, 27))
#define S_PARAMS_MSK	(GENMASK_32(26, 0))

/* GENI_STATUS fields */
#define M_GENI_CMD_ACTIVE	(BIT(0))
#define S_GENI_CMD_ACTIVE	(BIT(12))
#define M_CMD_DONE_EN	(BIT(0))
#define S_CMD_DONE_EN	(BIT(0))

#define M_OPCODE_SHIFT	27
#define S_OPCODE_SHIFT	27
#define M_TX_FIFO_WATERMARK_EN	(BIT(30))
#define UART_START_TX	0x1
#define UART_CTS_MASK	(BIT(1))
#define M_SEC_IRQ_EN	(BIT(31))
#define TX_FIFO_WC_MSK	(GENMASK_32(27, 0))
#define RX_FIFO_WC_MSK	(GENMASK_32(24, 0))

#define S_RX_FIFO_WATERMARK_EN	(BIT(26))
#define S_RX_FIFO_LAST_EN	(BIT(27))
#define M_RX_FIFO_WATERMARK_EN	(BIT(26))
#define M_RX_FIFO_LAST_EN	(BIT(27))

/* GENI_SER_M_CLK_CFG/GENI_SER_S_CLK_CFG */
#define SER_CLK_EN	(BIT(0))
#define CLK_DIV_MSK	(GENMASK_32(15, 4))
#define CLK_DIV_SHFT	4

/* SE_HW_PARAM_0 fields */
#define TX_FIFO_WIDTH_MSK	(GENMASK_32(29, 24))
#define TX_FIFO_WIDTH_SHFT	24
#define TX_FIFO_DEPTH_MSK	(GENMASK_32(21, 16))
#define TX_FIFO_DEPTH_SHFT	16

/* GENI SE QUP Registers */
#define QUP_HW_VER_REG		0x4
#define  QUP_SE_VERSION_2_5	0x20050000

#define writel(val, addr)	io_write32(addr, val)
#define readl(addr)		io_read32(addr)

/*
 * Predefined packing configuration of the serial engine (CFG0, CFG1 regs)
 * for uart mode.
 *
 * Defines following configuration:
 * - Bits of data per transfer word             8
 * - Number of words per fifo element           4
 * - Transfer from MSB to LSB or vice-versa     false
 */
#define UART_PACKING_CFG0   0xf
#define UART_PACKING_CFG1   0x0

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct geni_uart_data *pd =
		container_of(chip, struct geni_uart_data, chip);

	return io_pa_or_va(&pd->base, GENI_UART_REG_SIZE);
}

/**
 * geni_se_get_tx_fifo_depth() - Get the TX fifo depth of the serial engine
 * @base:	Pointer to the concerned serial engine.
 *
 * This function is used to get the depth i.e. number of elements in the
 * TX fifo of the serial engine.
 *
 * Return: TX fifo depth in units of FIFO words.
 */
static inline uint32_t geni_se_get_tx_fifo_depth(vaddr_t base)
{
	uint32_t tx_fifo_depth;

	tx_fifo_depth = ((readl(base + SE_HW_PARAM_0) & TX_FIFO_DEPTH_MSK) >>
			 TX_FIFO_DEPTH_SHFT);
	return tx_fifo_depth;
}

/**
 * geni_se_get_tx_fifo_width() - Get the TX fifo width of the serial engine
 * @base:	Pointer to the concerned serial engine.
 *
 * This function is used to get the width i.e. word size per element in the
 * TX fifo of the serial engine.
 *
 * Return: TX fifo width in bits
 */
static inline uint32_t geni_se_get_tx_fifo_width(vaddr_t base)
{
	uint32_t tx_fifo_width;

	tx_fifo_width = ((readl(base + SE_HW_PARAM_0) & TX_FIFO_WIDTH_MSK) >>
			 TX_FIFO_WIDTH_SHFT);
	return tx_fifo_width;
}

/**
 * qcom_geni_serial_poll_bit() - Poll reg bit until desired value or timeout.
 * @base:	Pointer to the concerned serial engine.
 * @offset:	Offset to register address.
 * @field:	AND bitmask for desired bit.
 * @set:	Desired bit value.
 *
 * This function is used to get the width i.e. word size per element in the
 * TX fifo of the serial engine.
 *
 * Return: true, when register bit equals desired value, false, when timeout
 * reached.
 */
static bool qcom_geni_serial_poll_bit(vaddr_t base, int offset,
				      int field, bool set)
{
	uint32_t reg;
	unsigned int baud;
	unsigned int tx_fifo_depth;
	unsigned int tx_fifo_width;
	unsigned int fifo_bits;
	unsigned long timeout_us = 10000;

	baud = 115200;

	tx_fifo_depth = geni_se_get_tx_fifo_depth(base);
	tx_fifo_width = geni_se_get_tx_fifo_width(base);
	fifo_bits = tx_fifo_depth * tx_fifo_width;
	/*
	 * Total polling iterations based on FIFO worth of bytes to be
	 * sent at current baud. Add a little fluff to the wait.
	 */
	timeout_us = ((fifo_bits * USEC_PER_SEC) / baud) + 500;

	timeout_us = DIV_ROUND_UP(timeout_us, 10) * 10;
	while (timeout_us) {
		reg = readl(base + offset);
		if ((bool)(reg & field) == set)
			return true;
		udelay(10);
		timeout_us -= 10;
	}
	return false;
}

static void qcom_geni_serial_setup_tx(vaddr_t base, uint32_t xmit_size)
{
	uint32_t m_cmd;

	writel(xmit_size, base + SE_UART_TX_TRANS_LEN);
	m_cmd = UART_START_TX << M_OPCODE_SHIFT;
	writel(m_cmd, base + SE_GENI_M_CMD0);
}

static inline void geni_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	qcom_geni_serial_poll_bit(base, SE_GENI_STATUS,
				  M_GENI_CMD_ACTIVE, false);

	qcom_geni_serial_setup_tx(base, 1);
	writel(ch, base + SE_GENI_TX_FIFOn);
}

static const struct serial_ops geni_uart_ops = {
	.putc = geni_uart_putc,
};
DECLARE_KEEP_PAGER(geni_uart_ops);

void geni_uart_init(struct geni_uart_data *pd, vaddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &geni_uart_ops;
}
