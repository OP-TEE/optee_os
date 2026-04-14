// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>

#include "diag_log.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, DIAG_BASE, DIAG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			(DIAG_LOG_START_INFO & ~SMALL_PAGE_MASK),
			SMALL_PAGE_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			(TCSR_BOOT_MISC_DETECT & ~SMALL_PAGE_MASK),
			SMALL_PAGE_SIZE);

#define DIAG_VERSION_V1		1
#define DIAG_MAGIC_INIT		0x47414944
#define DIAG_MAGIC_FAILED	0xDEADBEEF
#define DIAG_MAGIC_DLOAD	0xD15AB1ED
#define DLOAD_MAGIC_COOKIE	0x10

struct diag_hdr {
	uint32_t version;
	uint32_t magic;
};

struct diag_conf {
	uint32_t buf_offset;
	uint32_t buf_size;
};

struct circ_wo_buf {
	uint32_t wrap;
	uint32_t head;
	uint8_t buf[];
};

struct diag {
	struct diag_hdr hdr;
	struct diag_conf conf;
	struct circ_wo_buf wo_cbuf;
};

static struct diag *global_diag;

static struct diag *get_diag_region(void)
{
	struct diag *diag = NULL;
	uint32_t *tcsr_reg = NULL;

	tcsr_reg = phys_to_virt(TCSR_BOOT_MISC_DETECT, MEM_AREA_IO_SEC,
				sizeof(uint32_t));
	diag = phys_to_virt(DIAG_BASE, MEM_AREA_IO_SEC, DIAG_SIZE);

	if (!tcsr_reg || !diag) {
		EMSG("DIAG: Failed to map regions");
		return NULL;
	}

	if (io_read32((vaddr_t)tcsr_reg) == DLOAD_MAGIC_COOKIE) {
		diag->hdr.magic = DIAG_MAGIC_DLOAD;
		dsb();
		return NULL;
	}

	return diag;
}

void qcom_diag_log_init(void)
{
	struct diag *diag = NULL;
	uint32_t *diag_info_addr = NULL;

	if (!IS_ENABLED(CFG_QCOM_DIAG_LOG)) {
		IMSG("DIAG: Feature not available");
		return;
	}

	diag = get_diag_region();
	if (!diag)
		return;

	memset(diag, 0, DIAG_SIZE);

	diag->hdr.version = DIAG_VERSION_V1;
	diag->hdr.magic = DIAG_MAGIC_INIT;
	diag->conf.buf_offset = offsetof(struct diag, wo_cbuf.buf);
	diag->conf.buf_size = ROUNDDOWN2(DIAG_SIZE - diag->conf.buf_offset, 16);

	if (diag->conf.buf_offset >= DIAG_SIZE || diag->conf.buf_size == 0) {
		EMSG("DIAG: Invalid buffer configuration (offset=%u, size=%u)",
		     diag->conf.buf_offset, diag->conf.buf_size);
		diag->hdr.magic = DIAG_MAGIC_FAILED;
		return;
	}

	diag_info_addr = phys_to_virt(DIAG_LOG_START_INFO, MEM_AREA_IO_SEC,
				      2 * sizeof(uint32_t));
	if (diag_info_addr) {
		io_write32((vaddr_t)&diag_info_addr[0], DIAG_BASE);
		io_write32((vaddr_t)&diag_info_addr[1], DIAG_SIZE);
	}

	dsb();

	global_diag = diag;
}

void qcom_diag_log_puts(const char *str)
{
	struct diag *diag = global_diag;
	const char *p = NULL;

	if (!diag || !str)
		return;

	for (p = str; *p; p++) {
		diag->wo_cbuf.buf[diag->wo_cbuf.head++] = *p;
		if (diag->wo_cbuf.head >= diag->conf.buf_size) {
			diag->wo_cbuf.head = 0;
			if (diag->wo_cbuf.wrap < UINT32_MAX)
				diag->wo_cbuf.wrap++;
		}
	}
}
