/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

	return io_pa_or_va(&pd->base);
}

static void stih_asc_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!(read32(base + ASC_STATUS) & ASC_STATUS_TX_EMPTY))
		;
}

static void stih_asc_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	while (!(read32(base + ASC_STATUS) & ASC_STATUS_TX_HALF_EMPTY))
		;

	write32(ch, base + ASC_TXBUFFER);
}

static const struct serial_ops stih_asc_ops = {
	.flush = stih_asc_flush,
	.putc = stih_asc_putc,
};
KEEP_PAGER(stih_asc_ops);

void stih_asc_init(struct stih_asc_pd *pd, vaddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &stih_asc_ops;
}
