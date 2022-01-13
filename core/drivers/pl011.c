// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */
#include <assert.h>
#include <drivers/pl011.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <stdlib.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#define UART_DR		0x00 /* data register */
#define UART_RSR_ECR	0x04 /* receive status or error clear */
#define UART_DMAWM	0x08 /* DMA watermark configure */
#define UART_TIMEOUT	0x0C /* Timeout period */
/* reserved space */
#define UART_FR		0x18 /* flag register */
#define UART_ILPR	0x20 /* IrDA low-poer */
#define UART_IBRD	0x24 /* integer baud register */
#define UART_FBRD	0x28 /* fractional baud register */
#define UART_LCR_H	0x2C /* line control register */
#define UART_CR		0x30 /* control register */
#define UART_IFLS	0x34 /* interrupt FIFO level select */
#define UART_IMSC	0x38 /* interrupt mask set/clear */
#define UART_RIS	0x3C /* raw interrupt register */
#define UART_MIS	0x40 /* masked interrupt register */
#define UART_ICR	0x44 /* interrupt clear register */
#define UART_DMACR	0x48 /* DMA control register */

/* flag register bits */
#define UART_FR_RTXDIS	(1 << 13)
#define UART_FR_TERI	(1 << 12)
#define UART_FR_DDCD	(1 << 11)
#define UART_FR_DDSR	(1 << 10)
#define UART_FR_DCTS	(1 << 9)
#define UART_FR_RI	(1 << 8)
#define UART_FR_TXFE	(1 << 7)
#define UART_FR_RXFF	(1 << 6)
#define UART_FR_TXFF	(1 << 5)
#define UART_FR_RXFE	(1 << 4)
#define UART_FR_BUSY	(1 << 3)
#define UART_FR_DCD	(1 << 2)
#define UART_FR_DSR	(1 << 1)
#define UART_FR_CTS	(1 << 0)

/* transmit/receive line register bits */
#define UART_LCRH_SPS		(1 << 7)
#define UART_LCRH_WLEN_8	(3 << 5)
#define UART_LCRH_WLEN_7	(2 << 5)
#define UART_LCRH_WLEN_6	(1 << 5)
#define UART_LCRH_WLEN_5	(0 << 5)
#define UART_LCRH_FEN		(1 << 4)
#define UART_LCRH_STP2		(1 << 3)
#define UART_LCRH_EPS		(1 << 2)
#define UART_LCRH_PEN		(1 << 1)
#define UART_LCRH_BRK		(1 << 0)

/* control register bits */
#define UART_CR_CTSEN		(1 << 15)
#define UART_CR_RTSEN		(1 << 14)
#define UART_CR_OUT2		(1 << 13)
#define UART_CR_OUT1		(1 << 12)
#define UART_CR_RTS		(1 << 11)
#define UART_CR_DTR		(1 << 10)
#define UART_CR_RXE		(1 << 9)
#define UART_CR_TXE		(1 << 8)
#define UART_CR_LPE		(1 << 7)
#define UART_CR_OVSFACT		(1 << 3)
#define UART_CR_UARTEN		(1 << 0)

#define UART_IMSC_RTIM		(1 << 6)
#define UART_IMSC_RXIM		(1 << 4)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct pl011_data *pd =
		container_of(chip, struct pl011_data, chip);

	return io_pa_or_va(&pd->base, PL011_REG_SIZE);
}

static void pl011_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	/*
	 * Wait for the transmit FIFO to be empty.
	 * It can happen that Linux initializes the OP-TEE driver with the
	 * console UART disabled; avoid an infinite loop by checking the UART
	 * enabled flag. Checking it in the loop makes the code safe against
	 * asynchronous disable.
	 */
	while ((io_read32(base + UART_CR) & UART_CR_UARTEN) &&
	       !(io_read32(base + UART_FR) & UART_FR_TXFE))
		;
}

static bool pl011_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	return !(io_read32(base + UART_FR) & UART_FR_RXFE);
}

static int pl011_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!pl011_have_rx_data(chip))
		;
	return io_read32(base + UART_DR) & 0xff;
}

static void pl011_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	/* Wait until there is space in the FIFO or device is disabled */
	while (io_read32(base + UART_FR) & UART_FR_TXFF)
		;

	/* Send the character */
	io_write32(base + UART_DR, ch);
}

static const struct serial_ops pl011_ops = {
	.flush = pl011_flush,
	.getchar = pl011_getchar,
	.have_rx_data = pl011_have_rx_data,
	.putc = pl011_putc,
};
DECLARE_KEEP_PAGER(pl011_ops);

void pl011_init(struct pl011_data *pd, paddr_t pbase, uint32_t uart_clk,
		uint32_t baud_rate)
{
	vaddr_t base;

	pd->base.pa = pbase;
	pd->chip.ops = &pl011_ops;

	base = io_pa_or_va(&pd->base, PL011_REG_SIZE);

	/* Clear all errors */
	io_write32(base + UART_RSR_ECR, 0);
	/* Disable everything */
	io_write32(base + UART_CR, 0);

	if (baud_rate) {
		uint32_t divisor = (uart_clk * 4) / baud_rate;

		io_write32(base + UART_IBRD, divisor >> 6);
		io_write32(base + UART_FBRD, divisor & 0x3f);
	}

	/* Configure TX to 8 bits, 1 stop bit, no parity, fifo disabled. */
	io_write32(base + UART_LCR_H, UART_LCRH_WLEN_8);

	/* Enable interrupts for receive and receive timeout */
	io_write32(base + UART_IMSC, UART_IMSC_RXIM | UART_IMSC_RTIM);

	/* Enable UART and RX/TX */
	io_write32(base + UART_CR, UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE);

	pl011_flush(&pd->chip);
}

#ifdef CFG_DT

static struct serial_chip *pl011_dev_alloc(void)
{
	struct pl011_data *pd = nex_calloc(1, sizeof(*pd));

	if (!pd)
		return NULL;
	return &pd->chip;
}

static int pl011_dev_init(struct serial_chip *chip, const void *fdt, int offs,
			  const char *parms)
{
	struct pl011_data *pd = container_of(chip, struct pl011_data, chip);
	vaddr_t vbase;
	paddr_t pbase;
	size_t size;

	if (parms && parms[0])
		IMSG("pl011: device parameters ignored (%s)", parms);

	if (dt_map_dev(fdt, offs, &vbase, &size) < 0)
		return -1;

	if (size != 0x1000) {
		EMSG("pl011: unexpected register size: %zx", size);
		return -1;
	}

	pbase = virt_to_phys((void *)vbase);
	pl011_init(pd, pbase, 0, 0);

	return 0;
}

static void pl011_dev_free(struct serial_chip *chip)
{
	struct pl011_data *pd = container_of(chip, struct pl011_data, chip);

	nex_free(pd);
}

static const struct serial_driver pl011_driver = {
	.dev_alloc = pl011_dev_alloc,
	.dev_init = pl011_dev_init,
	.dev_free = pl011_dev_free,
};

static const struct dt_device_match pl011_match_table[] = {
	{ .compatible = "arm,pl011" },
	{ 0 }
};

DEFINE_DT_DRIVER(pl011_dt_driver) = {
	.name = "pl011",
	.type = DT_DRIVER_UART,
	.match_table = pl011_match_table,
	.driver = &pl011_driver,
};

#endif /* CFG_DT */
