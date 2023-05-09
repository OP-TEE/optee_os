// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2022, Linaro Limited
 */

#include <arch_main.h>
#include <config.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <optee_scmi.h>
#include <scmi/scmi_server.h>

/*
 * OP-TEE helper function exported to SCP-firmware
 */
uintptr_t smt_phys_to_virt(uintptr_t pa, size_t sz, bool shmem_is_secure)
{
	if (shmem_is_secure)
		return (uintptr_t)phys_to_virt(pa, MEM_AREA_IO_SEC, sz);
	else
		return (uintptr_t)phys_to_virt(pa, MEM_AREA_IO_NSEC, sz);
}

/*
 * SCMI server APIs exported to OP-TEE core
 */
int scmi_server_get_channels_count(void)
{
	return scmi_get_devices_count();
}

TEE_Result scmi_server_get_channel(unsigned int channel_id, int *handle)
{
	int fwk_id = 0;

	fwk_id = scmi_get_device(channel_id);
	if (fwk_id < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (handle)
		*handle = fwk_id;

	return TEE_SUCCESS;
}

TEE_Result scmi_server_smt_process_thread(unsigned int channel_id)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int fwk_id = 0;

	res = scmi_server_get_channel(channel_id, &fwk_id);
	if (!res)
		scmi_process_mbx_smt(fwk_id);

	return res;
}

TEE_Result scmi_server_msg_process_thread(unsigned int channel_id,
					  void *in_buf, size_t in_sz,
					  void *out_buf, size_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int fwk_id = 0;

	res = scmi_server_get_channel(channel_id, &fwk_id);
	if (!res)
		scmi_process_mbx_msg(fwk_id, in_buf, in_sz, out_buf, out_sz);

	return res;
}

static TEE_Result scmi_server_initialize(void)
{
	int rc = 0;

	rc = scmi_arch_init();
	if (rc < 0) {
		EMSG("SCMI server init failed: %d", rc);
		panic();
	}

	return TEE_SUCCESS;
}

boot_final(scmi_server_initialize);
