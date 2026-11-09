// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <boot_mode.h>
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

#include "provision.h"
#include "provision_backend.h"
#ifdef CFG_QCOM_PROVISION_SEC_ELF_V3
#include "sec_elf_v3.h"
#else
#include "sec_elf_v2.h"
#endif

/* Memory type of the window holding the data, a platform may override it */
#ifndef PROVISION_WINDOW_MEM_AREA
#define PROVISION_WINDOW_MEM_AREA	MEM_AREA_RAM_NSEC
#endif

#ifdef CFG_QCOM_PROVISION_SEC_ELF_V3
#define PROVISION_BACKEND	provision_backend_tme
#define PROVISION_EXECUTE	provision_execute_v3
#else
#define PROVISION_BACKEND	provision_backend_qfprom
#define PROVISION_EXECUTE(be, data, len, blown) \
	provision_execute(data, len, blown)
#endif

register_phys_mem(PROVISION_WINDOW_MEM_AREA, CFG_SEC_ELF_DDR_ADDR,
		  CFG_SEC_ELF_DDR_SIZE);

static TEE_Result execute_provisioning(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *snapshot = NULL;
	uint8_t *source = NULL;
	bool dload_mode = false;
	bool fuses_blown = false;

#ifndef CFG_QCOM_PROVISION_SEC_ELF_V3
	COMPILE_TIME_ASSERT(sizeof(struct secdat_hdr) <= CFG_SEC_ELF_DDR_SIZE);
#endif

	if (qcom_is_dload_mode(&dload_mode) != TEE_SUCCESS)
		panic("Failed to determine boot mode");
	if (dload_mode) {
		IMSG("Skipping fuse provisioning in download mode");
		return TEE_SUCCESS;
	}

	source = phys_to_virt(CFG_SEC_ELF_DDR_ADDR, PROVISION_WINDOW_MEM_AREA,
			      CFG_SEC_ELF_DDR_SIZE);
	if (!source)
		panic("Failed to map fuse provisioning input");

	/* Capture the bounded input before inspecting any fields. */
	snapshot = malloc(CFG_SEC_ELF_DDR_SIZE);
	if (!snapshot) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(snapshot, source, CFG_SEC_ELF_DDR_SIZE);

	/*
	 * The security processor calls below may never return, so the window
	 * must not stay readable until the end of the run.
	 */
	if (IS_ENABLED(CFG_QCOM_PROVISION_BACKEND_TME))
		memzero_explicit(source, CFG_SEC_ELF_DDR_SIZE);

	if (IS_ENABLED(CFG_QCOM_TME_ARB)) {
		res = provision_commit_rollback();
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = PROVISION_EXECUTE(&PROVISION_BACKEND, snapshot,
				CFG_SEC_ELF_DDR_SIZE, &fuses_blown);

out:
	free_wipe(snapshot);
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

/*
 * The security processor is reached through the FF-A communication service,
 * which is up only after the service group has run.
 */
#ifdef CFG_QCOM_PROVISION_BACKEND_TME
nex_driver_init_late(execute_provisioning);
#else
service_init(execute_provisioning);
#endif
