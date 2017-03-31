/*
 * Copyright (c) 2016, Linaro Limited
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
#include <compiler.h>
#include <drivers/pl050.h>
#include <io.h>
#include <keep.h>
#include <util.h>

#define KMI_ICR		0x00
#define KMI_STAT	0x04
#define KMI_DATA	0x08
#define KMI_CLKDIV	0x0c
#define KMI_IR		0x10

#define KMI_ICR_TYPE		(1 << 5)
#define KMI_ICR_RXINTERN	(1 << 4)
#define KMI_ICR_TXINTERN	(1 << 3)
#define KMI_ICR_EN		(1 << 2)
#define KMI_ICR_FKMID		(1 << 1)
#define KMI_ICR_FKMIC		(1 << 0)

#define KMI_STAT_TXEMPTY	(1 << 6)
#define KMI_STAT_TXBUSY		(1 << 5)
#define KMI_STAT_RXFULL		(1 << 4)
#define KMI_STAT_RXBUSY		(1 << 3)
#define KMI_STAT_RXPARITY	(1 << 2)
#define KMI_STAT_KMIC		(1 << 1)
#define KMI_STAT_KMID		(1 << 0)

#define KMI_IR_TXINTR		(1 << 1)
#define KMI_IR_RXINTR		(1 << 0)

static bool pl050_have_rx_data(struct serial_chip *chip)
{
	struct pl050_data *pd = container_of(chip, struct pl050_data, chip);

	return !!(read8(pd->base + KMI_STAT) & KMI_STAT_RXFULL);
}

static int pl050_getchar(struct serial_chip *chip)
{
	struct pl050_data *pd = container_of(chip, struct pl050_data, chip);

	while (!pl050_have_rx_data(chip))
		;
	return read8(pd->base + KMI_DATA);
}

static void pl050_flush(struct serial_chip *chip)
{
	struct pl050_data *pd = container_of(chip, struct pl050_data, chip);

	while (!(read8(pd->base + KMI_STAT) & KMI_STAT_TXEMPTY))
		;
}

static void pl050_putc(struct serial_chip *chip, int ch)
{
	struct pl050_data *pd = container_of(chip, struct pl050_data, chip);

	pl050_flush(chip);
	write8(ch, pd->base + KMI_DATA);
}

static const struct serial_ops pl050_ops = {
	.putc = pl050_putc,
	.flush = pl050_flush,
	.have_rx_data = pl050_have_rx_data,
	.getchar = pl050_getchar,
};
KEEP_PAGER(pl050_ops);

void pl050_init(struct pl050_data *pd, vaddr_t base, uint32_t clk)
{
	pd->base = base;
	pd->chip.ops = &pl050_ops;

	write8(KMI_ICR_RXINTERN | KMI_ICR_EN, pd->base + KMI_ICR);
	write8(clk, base + KMI_CLKDIV);
}
