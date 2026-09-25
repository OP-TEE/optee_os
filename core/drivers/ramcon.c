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

#define RAMCON_MAGIC	0x4e4f434d4152ULL	/* "RAMCON" */
#define RAMCON_HDR	16			/* magic, head */

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CFG_RAMCON_BASE, CFG_RAMCON_SIZE);

static vaddr_t base;

static void ramcon_putc(struct serial_chip *chip __unused, int ch)
{
	uint64_t head = io_read64(base + 8);

	io_write8(base + RAMCON_HDR + head % (CFG_RAMCON_SIZE - RAMCON_HDR), ch);
	io_write64(base + 8, head + 1);
}

static void ramcon_flush(struct serial_chip *chip __unused)
{
}

static const struct serial_ops ramcon_ops = {
	.putc = ramcon_putc,
	.flush = ramcon_flush,
};

void ramcon_init(struct ramcon_data *pd)
{
	base = (vaddr_t)phys_to_virt_io(CFG_RAMCON_BASE, CFG_RAMCON_SIZE);
	if (!base)
		return;
	if (io_read64(base) != RAMCON_MAGIC) {
		io_write64(base + 8, 0);
		io_write64(base, RAMCON_MAGIC);
	}
	pd->chip.ops = &ramcon_ops;
}
