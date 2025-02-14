// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/amd/mailbox_driver.h>
#include <initcall.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/thread_arch.h>
#include <mailbox_private.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <string.h>
#include <tee/cache.h>

static struct ipi_info ipi;

static TEE_Result mailbox_call(enum mailbox_api ipi_api, uint32_t blocking)
{
	struct thread_smc_args args = {
		.a0 = PLAT_SMC_SIP_IPI | ipi_api,
		.a1 = reg_pair_to_64(0, ipi.local),
		.a2 = reg_pair_to_64(0, ipi.remote),
		.a3 = reg_pair_to_64(0, blocking),
	};

	thread_smccc(&args);

	if (args.a0) {
		EMSG("Mailbox Call returned with error 0x%"PRIx64, args.a0);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result mailbox_open(uint32_t remote_id, size_t payload_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t req_addr = NULL;
	paddr_t rsp_addr = NULL;

	ipi.remote = remote_id;

	req_addr = ipi.buf + (remote_id * IPI_OFFSET_MULTIPLIER) +
		IPI_REQ_OFFSET;

	rsp_addr = ipi.buf + (remote_id * IPI_OFFSET_MULTIPLIER) +
		IPI_RESP_OFFSET;

	ipi.req = core_mmu_add_mapping(MEM_AREA_RAM_SEC,
				       req_addr,
				       payload_size);
	if (!ipi.req) {
		EMSG("Failed to map request buffer");
		ipi.remote = 0;
		return TEE_ERROR_GENERIC;
	}

	ipi.rsp = core_mmu_add_mapping(MEM_AREA_RAM_SEC,
				       rsp_addr,
				       payload_size);
	if (!ipi.rsp) {
		EMSG("Failed to map response buffer");
		/* Remove mapping for request buffer.
		 * Not checking return value res, since already in error case.
		 */
		res = core_mmu_remove_mapping(MEM_AREA_RAM_SEC,
					      ipi.req,
					      payload_size);
		/* Already in error condition */
		ipi.req = NULL;
		ipi.remote = 0;
		return TEE_ERROR_GENERIC;
	}

	mutex_lock(&ipi.lock);

	res = mailbox_call(IPI_MAILBOX_OPEN, IPI_BLOCK);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open Mailbox for remote ID %"PRIu32, remote_id);
		/* Reset IPI information structure.
		 * Not checking return value res, already in error case
		 */
		res = core_mmu_remove_mapping(MEM_AREA_RAM_SEC,
					      ipi.req,
					      payload_size);
		res = core_mmu_remove_mapping(MEM_AREA_RAM_SEC,
					      ipi.rsp,
					      payload_size);
		ipi.req = NULL;
		ipi.rsp = NULL;
		ipi.remote = 0;
		res = TEE_ERROR_GENERIC;
	}

	mutex_unlock(&ipi.lock);

	return res;
}

TEE_Result mailbox_release(uint32_t remote_id, size_t payload_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ipi.remote != remote_id) {
		EMSG("Mailbox not available for remote ID %"PRIu32, remote_id);
		return res;
	}

	mutex_lock(&ipi.lock);

	res = mailbox_call(IPI_MAILBOX_RELEASE, IPI_BLOCK);
	if (res != TEE_SUCCESS) {
		EMSG("Mailbox release failed for remote ID %"PRIu32, remote_id);
		goto out;
	}

	res = core_mmu_remove_mapping(MEM_AREA_RAM_SEC,
				      ipi.req,
				      payload_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to remove response mapping for remote ID %"PRIu32,
		     remote_id);
		goto out;
	}

	res = core_mmu_remove_mapping(MEM_AREA_RAM_SEC,
				      ipi.rsp,
				      payload_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to remove request mapping for remote ID %"PRIu32,
		     remote_id);
	}

	ipi.req = NULL;
	ipi.rsp = NULL;
	ipi.remote = 0;
out:
	mutex_unlock(&ipi.lock);
	return res;
}

static TEE_Result mailbox_write(uint32_t remote_id,
				void *payload,
				size_t payload_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ipi.remote != remote_id) {
		EMSG("Mailbox not available for remote ID %"PRIu32, remote_id);
		return res;
	}

	if (!IS_ALIGNED((uintptr_t)payload, CACHELINE_LEN)) {
		EMSG("payload address not aligned");
		return res;
	}

	if (!IS_ALIGNED(payload_size, CACHELINE_LEN)) {
		EMSG("payload size not aligned");
		return res;
	}

	memcpy(ipi.req, payload, payload_size);

	cache_operation(TEE_CACHEFLUSH, ipi.req, payload_size);

	return TEE_SUCCESS;
}

static TEE_Result mailbox_read(uint32_t remote_id,
			       void *payload,
			       size_t payload_size,
			       uint32_t *status)
{
	cache_operation(TEE_CACHEINVALIDATE, ipi.rsp, payload_size);

	*status = *(uint32_t *)ipi.rsp;

	if (*status)
		return TEE_ERROR_GENERIC;

	memcpy(ipi.rsp, payload, payload_size);

	return TEE_SUCCESS;
}

TEE_Result mailbox_notify(uint32_t remote_id,
			  void *payload,
			  size_t payload_size,
			  uint32_t blocking)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t remote_status = 0;

	if (ipi.remote != remote_id) {
		EMSG("Mailbox not available for remote ID %"PRIu32, remote_id);
		return res;
	}

	if (!ipi.req || !ipi.rsp) {
		EMSG("Request/Response buffers not mapped");
		return res;
	}

	mutex_lock(&ipi.lock);

	res = mailbox_write(ipi.remote, payload, payload_size);
	if (res) {
		EMSG("Can't write the request command");
		goto out;
	}

	res = mailbox_call(IPI_MAILBOX_NOTIFY, blocking);
	if (res) {
		EMSG("IPI error");
		goto out;
	}

	res = mailbox_read(ipi.remote, payload,
			   payload_size, &remote_status);
	if (res)
		EMSG("Can't read the remote response");

	if (remote_status)
		EMSG("Remote Status = %"PRIu32, remote_status);

out:
	mutex_unlock(&ipi.lock);
	return res;
}

static TEE_Result mailbox_init(void)
{
	ipi.local = CFG_MAILBOX_LOCAL_ID;
	ipi.buf = PLAT_IPI_BASE_ADDR +
		CFG_MAILBOX_LOCAL_ID * IPI_BASE_MULTIPLIER;

	mutex_init(&ipi.lock);

	DMSG("Initialized AMD Mailbox Service for Local ID %"PRIu32,
	     ipi.local);

	return TEE_SUCCESS;
}

service_init_late(mailbox_init);
