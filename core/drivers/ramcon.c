// SPDX-License-Identifier: BSD-2-Clause
/*
 * Console into a ring buffer at a fixed physical address, for boards where
 * the debug UART is not reachable. The window is mapped as non-secure device
 * memory so a normal-world reader sees every byte without cache maintenance.
 */
#include <compiler.h>
#include <drivers/ramcon.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <util.h>

#define RAMCON_MAGIC		0x4e4f434d4152ULL	/* "RAMCON" */
#define RAMCON_MAGIC_OFFS	0
#define RAMCON_HEAD_OFFS	8
#define RAMCON_HDR		16

static void ramcon_putc(struct serial_chip *chip, int ch)
{
	struct ramcon_data *pd = container_of(chip, struct ramcon_data, chip);
	vaddr_t base = io_pa_or_va(&pd->base, pd->size);
	uint64_t head = io_read64(base + RAMCON_HEAD_OFFS);
	size_t off = RAMCON_HDR + head % (pd->size - RAMCON_HDR);

	io_write8(base + off, ch);
	io_write64(base + RAMCON_HEAD_OFFS, head + 1);
}

static void ramcon_flush(struct serial_chip *chip __unused)
{
}

static const struct serial_ops ramcon_ops = {
	.putc = ramcon_putc,
	.flush = ramcon_flush,
};

void ramcon_init(struct ramcon_data *pd, paddr_t base, size_t size)
{
	vaddr_t va = 0;

	pd->base.pa = base;
	pd->size = size;
	pd->chip.ops = &ramcon_ops;

	va = io_pa_or_va(&pd->base, size);
	if (io_read64(va + RAMCON_MAGIC_OFFS) != RAMCON_MAGIC) {
		io_write64(va + RAMCON_HEAD_OFFS, 0);
		io_write64(va + RAMCON_MAGIC_OFFS, RAMCON_MAGIC);
	}
}
