// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021 Foundries.io Ltd
 */

#include <arm.h>
#include <drivers/zynqmp_pm.h>
#include <kernel/cache_helpers.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <utee_defines.h>

/*
 * For additional details about ZynqMP specific SMC ID's and PM request
 * handling in TF-A check
 * https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18842107/Arm+Trusted+Firmware
 */
#define EFUSE_ACCESS_SMC	0xC2000035
#define EFUSE_NOT_ENABLED	29

enum efuse_op { EFUSE_READ = 0, EFUSE_WRITE = 1 };

/*
 * Stores all required details to read/write efuse memory.
 * @src:        Physical address of the buffer to store the data to be
 *              written/read buffer
 * @size:       number of 32-bit words to be read/written
 * @offset:     offset in bytes to be read from/written to
 * @flag:       EFUSE_READ  - represents efuse read operation
 *              EFUSE_WRITE - represents efuse write operation
 * @pufuserfuse:0 - represents non-puf efuses, offset is used for read/write
 *              1 - represents puf user fuse row number.
 */
struct xilinx_efuse {
	uint64_t src;
	uint32_t size;
	uint32_t offset;
	uint32_t flag;
	uint32_t pufuserfuse;
};

static uint32_t zynqmp_sip_call(uint32_t pm_api_id, uint32_t arg0,
				uint32_t arg1, uint32_t arg2, uint32_t arg3,
				uint32_t *payload)
{
	struct thread_smc_args args = {
		.a0 = pm_api_id,
		.a1 = reg_pair_to_64(arg1, arg0),
		.a2 = reg_pair_to_64(arg3, arg2),
	};

	thread_smccc(&args);

	if (payload)
		*payload = args.a0 >> 32;

	return args.a0;
}

static void *alloc_aligned_zeroed(size_t *sz)
{
	size_t alloc_size = 0;
	size_t cacheline_size = 0;
	void *ptr = NULL;

	if (!sz)
		return NULL;

	alloc_size = *sz;
	cacheline_size = dcache_get_line_size();

	if (ROUNDUP_OVERFLOW(alloc_size, cacheline_size, &alloc_size))
		return NULL;

	ptr = memalign(cacheline_size, alloc_size);
	if (!ptr)
		return NULL;

	memset(ptr, 0, alloc_size);
	*sz = alloc_size;

	return ptr;
}

static TEE_Result efuse_op(enum efuse_op op, uint8_t *buf, size_t sz,
			   uint32_t efuse_offset, bool puf)
{
	paddr_t addr = 0;
	void *buf_aligned = NULL;
	size_t buf_aligned_sz = 0;
	struct xilinx_efuse efuse = { 0 };
	uint32_t res = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	buf_aligned_sz = sz;
	buf_aligned = alloc_aligned_zeroed(&buf_aligned_sz);
	if (!buf_aligned)
		return TEE_ERROR_OUT_OF_MEMORY;

	efuse.src = virt_to_phys(buf_aligned);
	efuse.size = sz / sizeof(uint32_t);
	efuse.offset = efuse_offset;
	efuse.flag = op;
	efuse.pufuserfuse = puf;

	cache_operation(TEE_CACHECLEAN, buf_aligned, buf_aligned_sz);
	cache_operation(TEE_CACHECLEAN, &efuse, sizeof(efuse));

	addr = virt_to_phys(&efuse);

	res = zynqmp_sip_call(EFUSE_ACCESS_SMC, addr >> 32, addr, 0, 0, NULL);
	if (res) {
		if (res == EFUSE_NOT_ENABLED)
			EMSG("Efuse access is not enabled");
		else
			EMSG("Error in efuse access %#"PRIx32, res);

		ret = TEE_ERROR_GENERIC;
	} else {
		if (op == EFUSE_READ) {
			cache_operation(TEE_CACHEINVALIDATE, buf_aligned,
					buf_aligned_sz);
			memcpy(buf, buf_aligned, sz);
		}
	}

	free(buf_aligned);

	return ret;
}

TEE_Result zynqmp_efuse_read(uint8_t *buf, size_t sz, uint32_t efuse_offset,
			     bool puf)
{
	return efuse_op(EFUSE_READ, buf, sz, efuse_offset, puf);
}
