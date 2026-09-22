// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/qfprom/qfprom.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <initcall.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#include "sec_elf_v2.h"

#define TCSR_BOOT_MISC_DLOAD	BIT(4)

register_phys_mem(MEM_AREA_RAM_NSEC, CFG_SEC_ELF_DDR_ADDR,
		  CFG_SEC_ELF_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_BOOT_MISC_DETECT,
			sizeof(uint32_t));

static TEE_Result execute_provisioning(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *snapshot = NULL;
	uint8_t *source = NULL;
	vaddr_t boot_misc_va = 0;
	bool fuses_blown = false;

	COMPILE_TIME_ASSERT(sizeof(struct secdat_hdr) <= CFG_SEC_ELF_DDR_SIZE);

	boot_misc_va = (vaddr_t)phys_to_virt(TCSR_BOOT_MISC_DETECT,
					  MEM_AREA_IO_SEC, sizeof(uint32_t));
	if (!boot_misc_va) {
		EMSG("Failed to map boot status");
		goto out;
	}
	if (io_read32(boot_misc_va) & TCSR_BOOT_MISC_DLOAD) {
		IMSG("Skipping fuse provisioning in download mode");
		return TEE_SUCCESS;
	}

	source = phys_to_virt(CFG_SEC_ELF_DDR_ADDR, MEM_AREA_RAM_NSEC,
			      CFG_SEC_ELF_DDR_SIZE);
	if (!source) {
		EMSG("Failed to map fuse provisioning input");
		goto out;
	}

	/* Capture the bounded input before inspecting any fields. */
	snapshot = malloc(CFG_SEC_ELF_DDR_SIZE);
	if (!snapshot) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(snapshot, source, CFG_SEC_ELF_DDR_SIZE);

	res = provision_execute(snapshot, CFG_SEC_ELF_DDR_SIZE, &fuses_blown);

out:
	free_wipe(snapshot);
	if (source)
		memzero_explicit(source, CFG_SEC_ELF_DDR_SIZE);

	if (res != TEE_SUCCESS) {
		EMSG("Fuse provisioning failed: %#"PRIx32, res);
		if (fuses_blown)
			EMSG("Fuse rows were programmed before the failure");
		panic("Fuse provisioning failed");
	}

	if (fuses_blown)
		provision_reset_device();

	return TEE_SUCCESS;
}

service_init(execute_provisioning);
