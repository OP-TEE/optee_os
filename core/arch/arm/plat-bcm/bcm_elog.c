// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <bcm_elog.h>
#include <io.h>

static struct bcm_elog global_elog;

void bcm_elog_putchar(char ch)
{
	struct bcm_elog *elog = &global_elog;
	uint32_t offset = 0, len = 0;
	vaddr_t base = 0;

	base = io_pa_or_va(&elog->base, elog->max_size);

	offset = io_read32(base + BCM_ELOG_OFF_OFFSET);
	len = io_read32(base + BCM_ELOG_LEN_OFFSET);
	io_write8(base + offset, ch);
	offset++;

	/* Log buffer is now full and need to wrap around */
	if (offset >= elog->max_size)
		offset = BCM_ELOG_HEADER_LEN;

	/* Only increment length when log buffer is not full */
	if (len < elog->max_size - BCM_ELOG_HEADER_LEN)
		len++;

	io_write32(base + BCM_ELOG_OFF_OFFSET, offset);
	io_write32(base + BCM_ELOG_LEN_OFFSET, len);
}

void bcm_elog_init(uintptr_t pa_base, uint32_t size)
{
	struct bcm_elog *elog = &global_elog;
	uint32_t val = 0;
	vaddr_t base = 0;

	elog->base.pa = pa_base;
	elog->max_size = size;

	base = io_pa_or_va(&elog->base, BCM_ELOG_HEADER_LEN);

	/*
	 * If a valid signature is found, it means logging is already
	 * initialized. In this case, we should not re-initialize the entry
	 * header in the designated memory
	 */
	val = io_read32(base + BCM_ELOG_SIG_OFFSET);
	if (val != BCM_ELOG_SIG_VAL) {
		io_write32(base + BCM_ELOG_SIG_OFFSET, BCM_ELOG_SIG_VAL);
		io_write32(base + BCM_ELOG_OFF_OFFSET, BCM_ELOG_HEADER_LEN);
		io_write32(base + BCM_ELOG_LEN_OFFSET, 0);
	}
}
