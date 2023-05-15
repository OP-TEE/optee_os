// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <compiler.h>
#include <io.h>
#include <kernel/spinlock.h>
#include <stdint.h>
#include <util.h>

#include "htif.h"

static unsigned int htif_global_lock __nex_bss = SPINLOCK_UNLOCK;

#ifdef HTIF_BASE
register_phys_mem(MEM_AREA_IO_NSEC, HTIF_BASE,
		  ROUNDUP(HTIF_REG_SIZE, CORE_MMU_PGDIR_SIZE));
#endif

void htif_lock_global(void)
{
	cpu_spin_lock(&htif_global_lock);
}

void htif_unlock_global(void)
{
	cpu_spin_unlock(&htif_global_lock);
}

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct htif_console_data *pd =
		container_of(chip, struct htif_console_data, chip);

	return io_pa_or_va(&pd->base, HTIF_REG_SIZE);
}

static void __maybe_unused tohost_cmd(vaddr_t base, uint64_t dev,
				      uint64_t cmd, uint64_t data)
{
	while (io_read64(base))
		barrier();

	io_write64(base, SHIFT_U64(dev, 56) | SHIFT_U64(cmd, 48) | data);
}

static void htif_console_putc(struct serial_chip *chip,
			      int ch __maybe_unused)
{
#ifdef RV64
	vaddr_t base = 0;

	htif_lock_global();
	base = chip_to_base(chip);
	tohost_cmd(base, HTIF_DEV_CONSOLE, HTIF_CMD_WRITE, ch);
	htif_unlock_global();
#else
#warning HTIF is not supported on RV32
#endif
}

static void htif_console_flush(struct serial_chip *chip __unused)
{
}

static const struct serial_ops htif_console_ops = {
	.flush = htif_console_flush,
	.putc = htif_console_putc,
};
DECLARE_KEEP_PAGER(htif_console_ops);

void htif_console_init(struct htif_console_data *pd, paddr_t pbase)
{
	pd->base.pa = pbase;
	pd->chip.ops = &htif_console_ops;
}
