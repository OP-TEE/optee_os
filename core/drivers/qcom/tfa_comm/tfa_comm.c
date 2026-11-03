// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Communication with the logical partition (LSP) of the TF-A EL3 SPMC.
 *
 * OP-TEE is an FF-A SP of the EL3 SPMC. It sends a service of the LSP a
 * FFA_MSG_SEND_DIRECT_REQ2 and gets a FFA_MSG_SEND_DIRECT_RESP2 back. Buffers
 * go through one page of secure memory shared with the LSP, whose address and
 * size come from the SP manifest. This driver knows the framing of the
 * messages (see tfa_comm_abi.h) and nothing about the services.
 */

#include <compiler.h>
#include <drivers/qcom/tfa_comm/tfa_comm.h>
#include <ffa.h>
#include <initcall.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/dt.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <kernel/thread_spmc.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>
#include <tee/uuid.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "tfa_comm_abi.h"

/* Description of the memory region of the SP manifest of the shared page */
#define TFA_COMM_SHMEM_DESC	"qcom,ffa-shmem"

/* The shared page: its lock, its mapping and its size */
static struct mutex shmem_mutex __nex_bss;
static void *shmem_va __nex_bss;
static size_t shmem_size __nex_bss;

/*
 * Pack the UUID of a service in x2 and x3: the 16 bytes of the UUID, in the
 * order of its text form, are read as two little-endian 64-bit numbers.
 */
static void uuid_to_regs(const TEE_UUID *uuid, uint64_t *x2, uint64_t *x3)
{
	uint8_t octets[sizeof(TEE_UUID)] = { };

	tee_uuid_to_octets(octets, uuid);
	*x2 = get_le64(octets);
	*x3 = get_le64(octets + sizeof(uint64_t));
}

static TEE_Result lsp_status_to_res(uint64_t status)
{
	switch (status) {
	case TFA_COMM_LSP_ST_SUCCESS:
		return TEE_SUCCESS;
	case TFA_COMM_LSP_ST_FAILURE:
		return TEE_ERROR_GENERIC;
	case TFA_COMM_LSP_ST_INVALID_PARAM:
		return TEE_ERROR_BAD_PARAMETERS;
	case TFA_COMM_LSP_ST_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case TFA_COMM_LSP_ST_DENIED:
		return TEE_ERROR_ACCESS_DENIED;
	default:
		EMSG("TFA_COMM: unknown LSP status %#"PRIx64, status);
		return TEE_ERROR_COMMUNICATION;
	}
}

static TEE_Result ffa_error_to_res(int32_t error)
{
	switch (error) {
	case FFA_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case FFA_INVALID_PARAMETERS:
		return TEE_ERROR_BAD_PARAMETERS;
	case FFA_DENIED:
		return TEE_ERROR_ACCESS_DENIED;
	case FFA_BUSY:
	case FFA_RETRY:
		return TEE_ERROR_BUSY;
	default:
		return TEE_ERROR_COMMUNICATION;
	}
}

/*
 * Copy the response of the LSP from the shared page to the output buffer of the
 * caller. @len is the size of the response that the LSP reports in x5.
 */
static TEE_Result copy_response(uint64_t len, void *out_buf, size_t *out_size)
{
	size_t capacity = out_size ? *out_size : 0;

	if (len > shmem_size) {
		EMSG("TFA_COMM: response %"PRIu64", shared memory %zu bytes",
		     len, shmem_size);
		return TEE_ERROR_COMMUNICATION;
	}

	if (len > capacity) {
		if (out_size)
			*out_size = len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (len) {
		dcache_inv_range(shmem_va, len);
		memcpy(out_buf, shmem_va, len);
	}
	if (out_size)
		*out_size = len;

	return TEE_SUCCESS;
}

TEE_Result tfa_comm_send_direct_req(const TEE_UUID *service_uuid,
				    uint64_t regs[TFA_COMM_NUM_REGS],
				    const void *in_buf, size_t in_size,
				    void *out_buf, size_t *out_size)
{
	struct thread_smc_1_2_regs args = { };
	TEE_Result res = TEE_SUCCESS;
	uint16_t own_id = 0;
	size_t i = 0;

	if (!shmem_va) {
		EMSG("TFA_COMM: not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	/* Validate the buffers */
	if (!service_uuid || !regs || (in_size && !in_buf) ||
	    (out_size && *out_size && !out_buf))
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_size > shmem_size) {
		EMSG("TFA_COMM: input %zu bytes, shared memory %zu bytes",
		     in_size, shmem_size);
		return TEE_ERROR_EXCESS_DATA;
	}

	mutex_lock(&shmem_mutex);

	if (in_size) {
		memcpy(shmem_va, in_buf, in_size);
		/* The LSP invalidates the page before it reads the request */
		dcache_clean_range(shmem_va, in_size);
	}

	/* Populate the registers, x4 is 0 and x5 is the size of the input */
	own_id = spmc_own_ffa_id();
	args.a0 = FFA_MSG_SEND_DIRECT_REQ2;
	args.a1 = SHIFT_U32(own_id, 16) | TFA_COMM_LSP_ID;
	uuid_to_regs(service_uuid, &args.a2, &args.a3);
	args.a4 = 0;
	args.a5 = in_size;
	for (i = 0; i < TFA_COMM_NUM_REGS; i++)
		args.a[TFA_COMM_FIRST_REG + i] = regs[i];

	thread_smccc_1_2(&args);

	if (args.a0 == FFA_MSG_SEND_DIRECT_RESP2 &&
	    FFA_SRC(args.a1) == TFA_COMM_LSP_ID && FFA_DST(args.a1) == own_id) {
		/* The registers are returned with every status of the LSP */
		for (i = 0; i < TFA_COMM_NUM_REGS; i++)
			regs[i] = args.a[TFA_COMM_FIRST_REG + i];

		res = lsp_status_to_res(args.a4);
		if (res == TEE_SUCCESS)
			res = copy_response(args.a5, out_buf, out_size);
	} else if (args.a0 == FFA_ERROR) {
		res = ffa_error_to_res((int32_t)args.a2);
		EMSG("TFA_COMM: FFA_ERROR %"PRId32, (int32_t)args.a2);
	} else {
		EMSG("TFA_COMM: unexpected response %#"PRIx64" %#"PRIx64,
		     args.a0, args.a1);
		res = TEE_ERROR_COMMUNICATION;
	}

	mutex_unlock(&shmem_mutex);

	return res;
}

/*
 * Get the address and the size of the shared page from the memory region of
 * the SP manifest that describes it:
 *
 * memory-regions {
 *	<any name> {
 *		description = "qcom,ffa-shmem";
 *		pages-count = <number of 4 KiB pages>;
 *		base-address = <address>;
 *	};
 * };
 */
static TEE_Result get_shmem_from_manifest(paddr_t *pa, size_t *size)
{
	const void *fdt = get_manifest_dt();
	const char *description = NULL;
	uint64_t base = 0;
	uint64_t pages = 0;
	int regions = 0;
	int node = 0;
	int len = 0;

	if (!fdt)
		return TEE_ERROR_ITEM_NOT_FOUND;

	regions = fdt_subnode_offset(fdt, 0, "memory-regions");
	if (regions < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	fdt_for_each_subnode(node, fdt, regions) {
		description = fdt_getprop(fdt, node, "description", &len);
		if (!description || len != (int)sizeof(TFA_COMM_SHMEM_DESC) ||
		    memcmp(description, TFA_COMM_SHMEM_DESC, len))
			continue;

		if (dt_getprop_as_number(fdt, node, "base-address", &base) ||
		    dt_getprop_as_number(fdt, node, "pages-count", &pages) ||
		    !base || !pages ||
		    MUL_OVERFLOW(pages, SMALL_PAGE_SIZE, size))
			return TEE_ERROR_BAD_FORMAT;

		*pa = base;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

/*
 * The SP manifest is only available until boot_final(), so this must run
 * before it. It runs after spmc_init(), which gets the FF-A ID of OP-TEE.
 */
static TEE_Result tfa_comm_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t pa = 0;
	size_t size = 0;

	mutex_init(&shmem_mutex);

	res = get_shmem_from_manifest(&pa, &size);
	if (res) {
		EMSG("TFA_COMM: no valid shared memory in the SP manifest");
		return res;
	}

	shmem_va = core_mmu_add_mapping(MEM_AREA_RAM_SEC, pa, size);
	if (!shmem_va) {
		EMSG("TFA_COMM: cannot map the shared memory at PA %#"PRIxPA,
		     pa);
		return TEE_ERROR_GENERIC;
	}
	shmem_size = size;

	DMSG("TFA_COMM: shared memory PA %#"PRIxPA" size %zu", pa, size);

	return TEE_SUCCESS;
}
nex_service_init_late(tfa_comm_init);
