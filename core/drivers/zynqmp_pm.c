// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021 Foundries.io Ltd
 */

#include <arm.h>
#include <drivers/zynqmp_pm.h>
#include <kernel/cache_helpers.h>
#include <kernel/tee_misc.h>
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
#define VERSION_ACCESS_SMC	0xC2000018

#define EFUSE_NOT_ENABLED	29
#define VERSION_MASK		GENMASK_32(3, 0)

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

	if (payload) {
		switch (pm_api_id) {
		case EFUSE_ACCESS_SMC:
			*payload = args.a0 >> 32;
			break;
		case VERSION_ACCESS_SMC:
			*payload = args.a1 & VERSION_MASK;
			break;
		default:
			break;
		}
	}

	return args.a0;
}

/*
 * Stores all required details to read/write eFuse memory.
 * @src:        Physical address of the buffer to store the data to be
 *              written/read (in LE)
 * @size:       number of 32-bit words to be read/written
 * @offset:     offset in bytes to be read from/written to
 * @flag:       EFUSE_READ  - represents eFuse read operation
 *              EFUSE_WRITE - represents eFuse write operation
 * @pufuserfuse:0 - represents non-PUF eFuses, offset is used for read/write
 *              1 - represents PUF user eFuse row number.
 */
struct xilinx_efuse {
	uint64_t src;
	uint32_t size;
	uint32_t offset;
	uint32_t flag;
	uint32_t pufuserfuse;
};

enum efuse_op { EFUSE_READ = 0, EFUSE_WRITE = 1 };

#define EFUSE_ELT(__x) \
	[__x] = { \
		.offset = ZYNQMP_EFUSE_##__x##_OFFSET, \
		.bytes = ZYNQMP_EFUSE_##__x##_LENGTH, \
	}

static const struct {
	uint32_t offset;
	uint32_t bytes;
} efuse_tbl[] = {
	EFUSE_ELT(DNA),
	EFUSE_ELT(IP_DISABLE),
	EFUSE_ELT(USER0),
	EFUSE_ELT(USER1),
	EFUSE_ELT(USER2),
	EFUSE_ELT(USER3),
	EFUSE_ELT(USER4),
	EFUSE_ELT(USER5),
	EFUSE_ELT(USER6),
	EFUSE_ELT(USER7),
	EFUSE_ELT(MISC_USER_CTRL),
	EFUSE_ELT(SEC_CTRL),
};

static TEE_Result efuse_op(enum efuse_op op, uint8_t *buf, size_t buf_sz,
			   enum zynqmp_efuse_id id, bool puf)
{
	struct xilinx_efuse *efuse_op = NULL;
	uint8_t *tmpbuf = NULL;
	paddr_t addr = 0;
	uint32_t efuse_ret = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	if (id >= ARRAY_SIZE(efuse_tbl)) {
		EMSG("Invalid efuse");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	efuse_op = alloc_cache_aligned(sizeof(*efuse_op));
	if (!efuse_op) {
		EMSG("Failed to allocate cache aligned buffer for operation");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	tmpbuf = alloc_cache_aligned(buf_sz);
	if (!tmpbuf) {
		EMSG("Failed to allocate cache aligned buffer for data");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (op == EFUSE_WRITE)
		memcpy(tmpbuf, buf, buf_sz);

	efuse_op->size = efuse_tbl[id].bytes / sizeof(uint32_t);
	efuse_op->offset = efuse_tbl[id].offset;
	efuse_op->src = virt_to_phys(tmpbuf);
	efuse_op->pufuserfuse = puf;
	efuse_op->flag = op;

	cache_operation(TEE_CACHECLEAN, tmpbuf, buf_sz);
	cache_operation(TEE_CACHECLEAN, efuse_op, sizeof(*efuse_op));

	addr = virt_to_phys(efuse_op);

	efuse_ret = zynqmp_sip_call(EFUSE_ACCESS_SMC, addr >> 32, addr, 0, 0,
				    NULL);
	if (efuse_ret) {
		if (efuse_ret == EFUSE_NOT_ENABLED)
			EMSG("eFuse access is not enabled");
		else
			EMSG("Error in eFuse access %#"PRIx32, efuse_ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (op == EFUSE_READ) {
		res = cache_operation(TEE_CACHEINVALIDATE, tmpbuf, buf_sz);
		if (res)
			goto out;
		memcpy(buf, tmpbuf, buf_sz);
	}

	res = TEE_SUCCESS;

out:
	free(tmpbuf);
	free(efuse_op);
	return res;
}

TEE_Result zynqmp_efuse_read(uint8_t *buf, size_t sz, enum zynqmp_efuse_id id,
			     bool puf)
{
	return efuse_op(EFUSE_READ, buf, sz, id, puf);
}

TEE_Result zynqmp_efuse_write(uint8_t *buf, size_t sz, enum zynqmp_efuse_id id,
			      bool puf)
{
	return efuse_op(EFUSE_WRITE, buf, sz, id, puf);
}

TEE_Result zynqmp_soc_version(uint32_t *version)
{
	uint32_t res = 0;

	if (!version)
		return TEE_ERROR_BAD_PARAMETERS;

	res = zynqmp_sip_call(VERSION_ACCESS_SMC, 0, 0, 0, 0, version);
	if (res) {
		EMSG("Failed to retrieve version");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
