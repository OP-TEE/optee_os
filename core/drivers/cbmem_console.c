// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Google Limited
 */

#include <compiler.h>
#include <console.h>
#include <drivers/cbmem_console.h>
#include <drivers/serial.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <types_ext.h>
#include <util.h>

#define CURSOR_MASK (BIT(28) - 1)
#define OVERFLOW BIT(31)

struct cbmem_console {
	uint32_t size;
	uint32_t cursor;
	uint8_t body[0];
};

struct cbmem_console_data {
	paddr_t base;
	struct cbmem_console *console;
	struct serial_chip chip;
	uint32_t size;
};

/*
 * Structures describing coreboot's in-memory descriptor tables. See
 * https://github.com/coreboot/coreboot/blob/ea2a38be323173075db3b13729a4006ea1fef72d/src/commonlib/include/commonlib/coreboot_tables.h
 * for canonical implementation.
 */

struct cb_header {
	uint8_t signature[4];
	uint32_t header_bytes;
	uint32_t header_checksum;
	uint32_t table_bytes;
	uint32_t table_checksum;
	uint32_t table_entries;
};

#define CB_TAG_CBMEM_CONSOLE 0x17

struct cb_entry {
	uint32_t tag;
	uint32_t size;
	uint64_t value;
};

static struct cbmem_console_data cbmem_console;

static void cbmem_console_flush(struct serial_chip *chip __unused)
{
}

static int cbmem_console_getchar(struct serial_chip *chip __unused)
{
	return 0;
}

static bool cbmem_console_have_rx_data(struct serial_chip *chip __unused)
{
	return false;
}

static void cbmem_console_putc(struct serial_chip *chip, int ch)
{
	struct cbmem_console_data *pd =
		container_of(chip, struct cbmem_console_data, chip);
	struct cbmem_console *c = pd->console;

	if (!pd->size)
		return;

	if ((c->cursor & CURSOR_MASK) + 1 >= pd->size) {
		c->cursor &= ~CURSOR_MASK;
		c->cursor |= OVERFLOW;
		c->body[0] = (uint8_t)(ch & 0xFF);
	} else {
		c->body[c->cursor & CURSOR_MASK] = (uint8_t)(ch & 0xFF);
		c->cursor++;
	}
}

static const struct serial_ops cbmem_console_ops = {
	.flush = cbmem_console_flush,
	.getchar = cbmem_console_getchar,
	.have_rx_data = cbmem_console_have_rx_data,
	.putc = cbmem_console_putc,
};
DECLARE_KEEP_PAGER(cbmem_console_ops);

static paddr_t get_cbmem_console_from_coreboot_table(paddr_t table_addr,
						     size_t table_size)
{
	struct cb_header *header = NULL;
	void *ptr = NULL;
	uint32_t i = 0;
	struct cb_entry *entry = NULL;
	paddr_t cbmem_console_base = 0;
	void *base = NULL;

	base = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, table_addr, table_size);
	if (!base)
		return 0;

	header = (struct cb_header *)base;
	if (memcmp(header->signature, "LBIO", 4))
		goto done;

	if (header->header_bytes + header->table_bytes > table_size)
		goto done;

	ptr = (uint8_t *)base + header->header_bytes;
	for (i = 0; i < header->table_entries; ++i) {
		entry = (struct cb_entry *)ptr;
		if ((uint8_t *)ptr >= (uint8_t *)base + table_size -
				sizeof(struct cb_entry)) {
			goto done;
		}

		switch (get_le32(&entry->tag)) {
		case CB_TAG_CBMEM_CONSOLE:
			cbmem_console_base = get_le64(&entry->value);
			goto done;
		default:
			/* We skip all but one tag type. */
			break;
		}

		ptr = (uint8_t *)ptr + get_le32(&entry->size);
	}

done:
	core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, base, table_size);
	return cbmem_console_base;
}

bool cbmem_console_init_from_dt(void *fdt)
{
	int offset = 0;
	paddr_t cb_addr = 0;
	size_t cb_size = 0;
	paddr_t cbmem_console_base = 0;

	if (!fdt)
		return false;

	offset = fdt_path_offset(fdt, "/firmware/coreboot");
	if (offset < 0)
		return false;

	cb_addr = fdt_reg_base_address(fdt, offset);
	cb_size = fdt_reg_size(fdt, offset);

	cbmem_console_base = get_cbmem_console_from_coreboot_table(cb_addr,
								   cb_size);
	if (!cbmem_console_base)
		return false;

	cbmem_console.base = cbmem_console_base;
	cbmem_console.console = (struct cbmem_console *)
		core_mmu_add_mapping(MEM_AREA_RAM_NSEC, cbmem_console_base,
				     sizeof(struct cbmem_console));
	if (!cbmem_console.console)
		return false;

	/*
	 * Copy the size now to prevent non-secure world from spoofing
	 * it later.
	 */
	cbmem_console.size = cbmem_console.console->size;
	cbmem_console.chip.ops = &cbmem_console_ops;

	register_serial_console(&cbmem_console.chip);
	return true;
}
