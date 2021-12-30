// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Devendra Devadiga.
 */

#include <bootlog.h>
#include <io.h>

static struct bootlog global_bootlog;

void boot_log_putchar(char ch)
{
	struct bootlog *blog = &global_bootlog;
	uint32_t len = 0;
	vaddr_t base = 0;
	base = io_pa_or_va(&blog->base, blog->bootlog_max_size);

	len = io_read32(base + BOOT_LOG_CUR_LEN_OFF);

	len = len & 0xFFFFF;
	io_write8(base + len + BOOT_LOG_HEADER_SIZE, ch);
	len++;
	len = len & 0xFFFFF;

	/* Boot log buffer is now full and need to start from beginning */
	if (len >= BOOT_LOG_MAX_SIZE)
		len = 0;

	io_write32(base + BOOT_LOG_CUR_LEN_OFF, len);
}

void boot_log_init(uintptr_t pa_base, uint32_t size)
{
	struct bootlog *blog = &global_bootlog;
	uint32_t val = 0;
	vaddr_t base = 0;

	blog->base.pa = pa_base;
	blog->bootlog_max_size = size;

	base = io_pa_or_va(&blog->base, BOOT_LOG_HEADER_SIZE);

	/*
	 * Check predefined signature is present or not.
	 * If found means boot logging is already initalized.
	 * If not found initialize boot logging by writing valid signature 
	 * in buffer header.
	 */
	val = io_read32(base + BOOT_LOG_SIG_OFFSET);
	if (val != BOOT_LOG_SIG_VAL) {
		io_write32(base + BOOT_LOG_SIG_OFFSET, BOOT_LOG_SIG_VAL);
		io_write32(base + BOOT_LOG_CUR_LEN_OFF, 0);	
		DMSG("Bootlog setup done in core.");
	}
}
