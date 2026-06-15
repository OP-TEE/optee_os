// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Rockchip Electronics Co., Ltd.
 */

#include <common.h>
#include <crypto/crypto.h>
#include <drivers/rockchip_otp.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

/* DDR firewall offsets (from TF-A rk3576/drivers/secure/firewall.h) */
#define FW_SGRF_DDR_RGN(i)		(0x0100 + (i) * 0x4)
#define FW_SGRF_DDR_RGN_CNT		16
#define FW_SGRF_DDR_CON			0x0168

/* base / (top - 1) encoded in 1 MB units, both clamped to 15 bits. */
#define RG_MAP_SECURE(top_mb, base_mb) \
	(((((top_mb) - 1) & 0x7fff) << 16) | ((base_mb) & 0x7fff))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SYS_SGRF_FW_BASE, SYS_SGRF_FW_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_S_BASE, OTP_S_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_base = (vaddr_t)phys_to_virt_io(SYS_SGRF_FW_BASE,
						   SYS_SGRF_FW_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);

	if (!fw_base)
		panic("SYS_SGRF_FW_BASE not mapped");

	assert(rgn >= 1 && rgn < FW_SGRF_DDR_RGN_CNT);
	assert(st < ed);
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%" PRIxPA "-0x%" PRIxPA,
	     rgn, st, ed);

	io_write32(fw_base + FW_SGRF_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_mb, st_mb));
	io_setbits32(fw_base + FW_SGRF_DDR_CON, BIT(rgn));

	return 0;
}

static struct mutex huk_mutex = MUTEX_INITIALIZER;
static struct tee_hw_unique_key *huk_cache;

static TEE_Result read_huk_from_otp(struct tee_hw_unique_key *hwkey)
{
	uint32_t buf[ROCKCHIP_OTP_HUK_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	static_assert(sizeof(buf) == sizeof(hwkey->data));

	res = rockchip_otp_read_secure(buf, ROCKCHIP_OTP_HUK_INDEX,
				       ROCKCHIP_OTP_HUK_SIZE);
	if (res)
		goto out;

	/* All-zero means the row has never been programmed */
	for (i = 0; i < ARRAY_SIZE(buf); i++) {
		if (buf[i] != 0) {
			memcpy(hwkey->data, buf, sizeof(hwkey->data));
			goto out;
		}
	}
	res = TEE_ERROR_NO_DATA;

out:
	memzero_explicit(buf, sizeof(buf));
	return res;
}

static TEE_Result generate_huk_from_prng(struct tee_hw_unique_key *hwkey)
{
	uint8_t buf[HW_UNIQUE_KEY_LENGTH] = { };
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;
	bool all_zero = true;

	res = crypto_rng_read(buf, sizeof(buf));
	if (res)
		goto out;

	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != 0) {
			all_zero = false;
			break;
		}
	}
	if (all_zero) {
		res = TEE_ERROR_NO_DATA;
		goto out;
	}

	memcpy(hwkey->data, buf, sizeof(hwkey->data));

out:
	memzero_explicit(buf, sizeof(buf));
	return res;
}

#ifdef CFG_RK3576_PERSIST_HUK
static TEE_Result write_huk_to_otp(const struct tee_hw_unique_key *hwkey)
{
	uint32_t buf[ROCKCHIP_OTP_HUK_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;

	static_assert(sizeof(buf) == sizeof(hwkey->data));

	memcpy(buf, hwkey->data, sizeof(buf));
	res = rockchip_otp_write_secure(buf, ROCKCHIP_OTP_HUK_INDEX,
					ROCKCHIP_OTP_HUK_SIZE);
	memzero_explicit(buf, sizeof(buf));
	return res;
}
#endif /* CFG_RK3576_PERSIST_HUK */

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&huk_mutex);

	if (huk_cache) {
		memcpy(hwkey->data, huk_cache->data, sizeof(hwkey->data));
		goto out;
	}

	huk_cache = malloc(sizeof(*huk_cache));
	if (!huk_cache) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Try the Secure OTP first */
	res = read_huk_from_otp(huk_cache);
	if (res == TEE_SUCCESS)
		goto copy;

	if (res != TEE_ERROR_NO_DATA) {
		EMSG("OTP HUK read failed: 0x%x", res);
		goto fail;
	}

	/*
	 * OTP slot is empty -- generate an ephemeral HUK from the PRNG.
	 * Enable CFG_RK3576_PERSIST_HUK to fuse it into OTP (irreversible).
	 */
	res = generate_huk_from_prng(huk_cache);
	if (res) {
		EMSG("HUK generation failed: 0x%x", res);
		goto fail;
	}

#ifdef CFG_RK3576_PERSIST_HUK
	res = write_huk_to_otp(huk_cache);
	if (res) {
		EMSG("OTP HUK write failed: 0x%x", res);
		goto fail;
	}
	IMSG("HUK persisted to Secure OTP");
#else
	IMSG("using ephemeral HUK (CFG_RK3576_PERSIST_HUK=n)");
#endif

copy:
	memcpy(hwkey->data, huk_cache->data, sizeof(hwkey->data));
	goto out;

fail:
	free_wipe(huk_cache);
	huk_cache = NULL;

out:
	mutex_unlock(&huk_mutex);
	return res;
}
