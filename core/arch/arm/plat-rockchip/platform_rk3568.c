// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 */

#include <common.h>
#include <cru.h>
#include <io.h>
#include <otp.h>
#include <kernel/panic.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <string_ext.h>
#include <utee_defines.h>

#define FIREWALL_DDR_FW_DDR_RGN(i) ((i)*0x4)
#define FIREWALL_DDR_FW_DDR_CON_REG 0x80
#define FIREWALL_DDR_FW_DDR_RGN_NUM 8
#define FIREWALL_DDR_FW_DDR_MST_NUM 6

#define RG_MAP_SECURE(top, base) ((((top)-1) << 16) | (base))

#define HW_UNIQUE_KEY_INDEX 0x2B0

#define TRNG_RNG_CTL 0x0400
#define TRNG_CTL_START 0xffff0037
#define TRNG_CTL_STOP 0xffff0000

#define TRNG_RNG_SAMPLE_CNT 0x0404
#define TRNG_READY_MASK 0x01
#define TRNG_RNG_DOUT_0 0x0410
#define TRNG_RNG_DOUT(x) (TRNG_RNG_DOUT_0 + (x * 4))

// A sample count of 1079 comes from rockchips optee solution
#define TRNG_SAMPLE_COUNT 1079
#define TRNG_POLL_PERIOD_US 0
#define TRNG_POLL_TIMEOUT_US 1000
#define TRNG_TIMEOUT_INIT 50000

#define TRNG_MAX_WORDS 8
#define TRNG_MAX_BYTES (TRNG_MAX_WORDS * sizeof(uint32_t))

#define TRNG_BLOCK_SIZE 32

#define CRU_TRNG_CTRL_OFFSET 0x320
#define CRU_TRNG_ENABLE 0x80000000
#define CRU_TRNG_DISABLE 0x80008000

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_S_BASE, OTP_S_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SGRF_BASE, SGRF_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTPC_PHY_BASE, OTPC_PHY_SIZE);

uint8_t cpu_id[16];

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_base =
		(vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_K(128);
	uint32_t ed_mb = ed / SIZE_K(128);

	if (!fw_base)
		panic();

	assert(rgn <= 7);
	assert(st < ed);

	/* Check aligned 4K */
	assert(st % SIZE_K(128) == 0);
	assert(ed % SIZE_K(128) == 0);

	DMSG("%s:%d protecting region %d: 0x%lx-0x%lx", __func__, __LINE__, rgn,
	     st, ed);

	/* Map top and base */
	io_write32(fw_base + FIREWALL_DDR_FW_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_mb, st_mb));

	/* Enable secure setting */
	io_setbits32(fw_base + FIREWALL_DDR_FW_DDR_CON_REG, BIT(rgn));

	return 0;
}

static void rk_tring_enable(vaddr_t cru)
{
	io_write32(cru + CRU_TRNG_CTRL_OFFSET, CRU_TRNG_ENABLE);
}

static void rk_tring_disable(vaddr_t cru)
{
	io_write32(cru + CRU_TRNG_CTRL_OFFSET, CRU_TRNG_DISABLE);
}

static int rk_trng_once(uint8_t *data, uint32_t size)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(TRNG_S_BASE, TRNG_S_SIZE);
	uint32_t buffer[TRNG_MAX_WORDS] = { 0 };
	int timeout = TRNG_TIMEOUT_INIT;
	bool timed_out = false;

	if (!data || size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size > TRNG_MAX_BYTES)
		size = TRNG_MAX_BYTES;

	/* Configure TRNG */
	io_write32(base + TRNG_RNG_SAMPLE_CNT, TRNG_SAMPLE_COUNT);
	io_write32(base + TRNG_RNG_CTL, TRNG_CTL_START);

	/* Wait for RNG ready */
	while (io_read32(base + TRNG_RNG_CTL) & TRNG_READY_MASK) {
		if (--timeout == 0) {
			timed_out = true;
			break;
		}
	}

	if (!timed_out) {
		/* Read whatever data is available */
		for (int i = 0; i < TRNG_MAX_WORDS; i++) {
			buffer[i] = io_read32(base + TRNG_RNG_DOUT(i));
		}

		io_write32(base + TRNG_RNG_CTL, TRNG_CTL_STOP);

		memcpy(data, buffer, size);

#if 0
		DMSG("%s:%d HW TRNG ONCE: %2X %2X %2X %2X %2X %2X %2X %2X\n",  __func__, __LINE__,
			buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5],buffer[5],buffer[7]);
#endif
	}

	return timed_out ? TEE_ERROR_TIMEOUT : TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *vdata, size_t len)
{
	size_t full_len;
	uint8_t *data = vdata;
	TEE_Result res = TEE_SUCCESS;
	vaddr_t cru = (vaddr_t)phys_to_virt_io(CRU_NS_BASE, CRU_NS_SIZE);

	if (!data || len == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rk_tring_enable(cru);

	full_len = len & ~(TRNG_BLOCK_SIZE - 1);

	for (size_t offset = 0; offset < full_len; offset += TRNG_BLOCK_SIZE) {
		res = rk_trng_once(data + offset, TRNG_BLOCK_SIZE);
		if (res != TEE_SUCCESS)
			goto out;
	}

	/* Handle remaining bytes */
	size_t remaining = len & (TRNG_BLOCK_SIZE - 1);
	if (remaining) {
		res = rk_trng_once(data + full_len, remaining);
	}

out:
	rk_tring_disable(cru);

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t buffer[HW_UNIQUE_KEY_LENGTH] = {};
	bool key_is_empty = true;
	size_t i = 0;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (rk_otp_s_read(HW_UNIQUE_KEY_INDEX, HW_UNIQUE_KEY_LENGTH, buffer) !=
	    0) {
		EMSG("%s:%d OTP: failed to read HW KEY from S OTP", __func__,
		     __LINE__);
		res = TEE_ERROR_NO_DATA;
		goto out;
	}

	/* Check if the buffer is all zero => HUK not present */
	for (i = 0; i < ARRAY_SIZE(buffer); i++) {
		if (buffer[i] != 0)
			key_is_empty = false;
	}

	if (key_is_empty) {
		/* Generate random 128-bit key from TRNG */
		res = hw_get_random_bytes(buffer, sizeof(buffer));
#if 0
		DMSG("RNG READ HW KEY: %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X %2X\n",
			buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5],buffer[5],buffer[7],
			buffer[8],buffer[9],buffer[10],buffer[11],buffer[12],buffer[13],buffer[14],buffer[15]
		);
#endif
		if (res)
			goto out;

		/* Write the new HUK into OTP at HW_UNIQUE_KEY_INDEX */
		res = rk_otp_s_write(HW_UNIQUE_KEY_INDEX, HW_UNIQUE_KEY_LENGTH,
				     buffer);
		if (res)
			goto out;
	}
	/* Copy HUK into hwkey->data */
	memcpy(hwkey->data, buffer, HW_UNIQUE_KEY_LENGTH);

out:
	/* Clear buffer memory */
	memzero_explicit(buffer, sizeof(buffer));

	return res;
}

int platform_secure_init(void)
{
	if (rk_otp_init() != 0) {
		EMSG("%s:%d: OTP: rk_otp_init failed", __func__, __LINE__);
		return -1;
	}

	if (rk_otp_ns_read(0x0A, 16, cpu_id) != 0) {
		EMSG("%s:%d: OTP: failed to read CPU ID from OTP", __func__,
		     __LINE__);
		return -1;
	}

	return 0;
}
