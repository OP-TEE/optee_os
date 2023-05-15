// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <drivers/stih_asc.h>
#include <io.h>
#include <keep.h>
#include <util.h>

#define ASC_BAUDRATE		0x00
#define ASC_TXBUFFER		0x04
#define ASC_STATUS		0x14

#define ASC_STATUS_TX_EMPTY		BIT(1)
#define ASC_STATUS_TX_HALF_EMPTY	BIT(2)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct stih_asc_pd *pd =
		container_of(chip, struct stih_asc_pd, chip);

	return io_pa_or_va(&pd->base, STIH_ASC_REG_SIZE);
}

static void stih_asc_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + ASC_STATUS) & ASC_STATUS_TX_EMPTY))
		;
}

static void stih_asc_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + ASC_STATUS) & ASC_STATUS_TX_HALF_EMPTY))
		;

	io_write32(base + ASC_TXBUFFER, ch);
}

static const struct serial_ops stih_asc_ops = {
	.flush = stih_asc_flush,
	.putc = stih_asc_putc,
};
DECLARE_KEEP_PAGER(stih_asc_ops);

void stih_asc_init(struct stih_asc_pd *pd, vaddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &stih_asc_ops;
}
