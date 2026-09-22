// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/qfprom/qfprom.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <initcall.h>
#include <inttypes.h>
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

#include "sec_elf_v2.h"

register_phys_mem(MEM_AREA_RAM_NSEC, CFG_SEC_ELF_DDR_ADDR,
		  CFG_SEC_ELF_DDR_SIZE);

static TEE_Result execute_provisioning(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *snapshot = NULL;
	uint8_t *source = NULL;
	bool fuses_blown = false;

	COMPILE_TIME_ASSERT(sizeof(struct secdat_hdr) <= CFG_SEC_ELF_DDR_SIZE);

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
