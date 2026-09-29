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
#include <trace.h>

#include "sec_elf_v2.h"

register_phys_mem(MEM_AREA_RAM_NSEC, CFG_SEC_ELF_DDR_ADDR,
		  CFG_SEC_ELF_DDR_SIZE);

static TEE_Result discover_sec_elf(const uint8_t **data_out, size_t *size)
{
	const struct secdat_hdr *hdr = NULL;
	const uint8_t *data = NULL;

	if (!data_out || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	data = phys_to_virt(CFG_SEC_ELF_DDR_ADDR, MEM_AREA_RAM_NSEC,
			    CFG_SEC_ELF_DDR_SIZE);
	if (!data) {
		EMSG("Failed to get VA for sec.elf at PA 0x%lx",
		     (unsigned long)CFG_SEC_ELF_DDR_ADDR);
		return TEE_ERROR_GENERIC;
	}

	hdr = (const struct secdat_hdr *)data;

	if (hdr->magic1 != SECDAT_MAGIC1 ||
	    hdr->magic2 != SECDAT_MAGIC2) {
		EMSG("Invalid sec.elf magic: 0x%"PRIx32 "/0x%"PRIx32,
		     hdr->magic1, hdr->magic2);
		return TEE_ERROR_BAD_FORMAT;
	}

	*size = sizeof(*hdr) + hdr->size + TEE_SHA256_HASH_SIZE;

	if (*size > CFG_SEC_ELF_DDR_SIZE) {
		EMSG("sec.elf size %zu exceeds limit %zu",
		     *size, (size_t)CFG_SEC_ELF_DDR_SIZE);
		return TEE_ERROR_BAD_FORMAT;
	}

	*data_out = data;
	return TEE_SUCCESS;
}

static TEE_Result execute_provisioning(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *data = NULL;
	bool fuses_blown = false;
	size_t len = 0;

	res = discover_sec_elf(&data, &len);
	if (res != TEE_SUCCESS)
		return res;

	res = provision_execute(data, len, &fuses_blown);
	if (res == TEE_ERROR_ACCESS_DENIED) {
		IMSG("Fuse provisioning locked - write permission denied");
		return TEE_SUCCESS;
	} else if (res != TEE_SUCCESS) {
		EMSG("Fuse provisioning failed: 0x%"PRIx32, res);
		return res;
	}

	if (fuses_blown) {
		IMSG("Fuse provisioning completed successfully");
		provision_reset_device();
	}

	return TEE_SUCCESS;
}

service_init(execute_provisioning);
