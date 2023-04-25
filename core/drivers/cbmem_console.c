// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 */

#include <compiler.h>
#include <console.h>
#include <drivers/cbmem_console.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <util.h>

#define CURSOR_MASK (BIT(28) - 1)
#define OVERFLOW BIT(31)

/*
 * Structures describing coreboot's in-memory descriptor tables. See
 * <coreboot>/src/commonlib/include/commonlib/coreboot_tables.h for
 * canonical implementation.
 */

struct cb_header {
	char signature[4];
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
	uint64_t uint64;
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
	if (pd->size == 0)
		return;

	if ((pd->console->cursor & CURSOR_MASK) + 1 >= pd->size) {
		pd->console->cursor &= ~CURSOR_MASK;
		pd->console->cursor |= OVERFLOW;
		pd->console->body[0] = (uint8_t)(ch & 0xFF);
	} else {
		pd->console->body[pd->console->cursor & CURSOR_MASK] =
			(uint8_t)(ch & 0xFF);
		pd->console->cursor++;
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
	struct cb_header *header;
	void *ptr;
	uint32_t i;
	struct cb_entry *entry;
	paddr_t cbmem_console_base = 0;
	void *base = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, table_addr,
					     table_size);
	if (!base)
		return 0;

	header = (struct cb_header *)base;
	if (strncmp(header->signature, "LBIO", 4))
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
			cbmem_console_base = get_le64(&entry->uint64);
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
	int offset;
	paddr_t cb_addr;
	size_t cb_size;
	paddr_t cbmem_console_base;

	if (!fdt)
		return false;

	offset = fdt_path_offset(fdt, "/firmware/coreboot");
	if (offset < 0)
		return false;

	cb_addr = _fdt_reg_base_address(fdt, offset);
	cb_size = _fdt_reg_size(fdt, offset);

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
