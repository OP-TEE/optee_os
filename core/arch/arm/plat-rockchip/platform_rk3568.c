// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Daniel Golle <daniel@makrotopia.org>
 */

#include <crypto/crypto.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

/* DDR firewall (from TF-A rk3568/drivers/secure/secure.h) */
#define FIREWALL_DDR_RGN(i)		((i) * 0x4)
#define FIREWALL_DDR_RGN_CNT		16
#define FIREWALL_DDR_CON		0x80

/*
 * base / (top - 1) encoded in 128 KiB blocks (not the 1 MiB blocks
 * used on RK3576/RK3588), both clamped to 15 bits.
 */
#define RG_MAP_SECURE(top, base) \
	(((((top) - 1) & 0x7fff) << 16) | ((base) & 0x7fff))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_base = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE,
						   FIREWALL_DDR_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_blk = st / SIZE_K(128);
	uint32_t ed_blk = ed / SIZE_K(128);

	if (!fw_base)
		panic("FIREWALL_DDR_BASE not mapped");

	/*
	 * Validate at runtime, not with assert(): a misaligned or
	 * out-of-range region would otherwise be silently truncated by the
	 * block division in a release build (NDEBUG), leaving part of the
	 * secure DRAM reachable from the normal world. Fail closed instead.
	 */
	if (rgn < 1 || rgn >= FIREWALL_DDR_RGN_CNT || st >= ed ||
	    st % SIZE_K(128) || ed % SIZE_K(128) || ed_blk > 0x8000)
		panic("invalid secure DDR region");

	DMSG("protecting region %d: 0x%" PRIxPA "-0x%" PRIxPA, rgn, st, ed);

	io_write32(fw_base + FIREWALL_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_blk, st_blk));
	io_setbits32(fw_base + FIREWALL_DDR_CON, BIT(rgn));

	return 0;
}

/*
 * Secure standalone TRNG (TRNG_S), same programming model as the RNG
 * sub-block of the crypto v2 IP (RK3568 TRM-Part2, section 5.4.1) driven
 * by the Linux rockchip-rng.c rk3568 variant, but the secure instance at
 * 0xfe370000 clocked from the secure CRU. Only the secure instance is
 * used: the non-secure TRNG at 0xfe388000 (its registers, CRU gates and
 * reset) is reachable from the normal world, so it must never source
 * secure entropy such as the HUK or the PRNG seed.
 */
#define TRNG_RNG_CTL			0x0400
#define TRNG_RNG_CTL_LEN_256_BIT	SHIFT_U32(0x03, 4)
#define TRNG_RNG_CTL_OSC_RING_SPEED_0	SHIFT_U32(0x00, 2)
#define TRNG_RNG_CTL_MASK		GENMASK_32(15, 0)
#define TRNG_RNG_CTL_ENABLE		BIT(1)
#define TRNG_RNG_CTL_START		BIT(0)
#define TRNG_RNG_SAMPLE_CNT		0x0404
#define TRNG_RNG_DOUT			0x0410

/*
 * TRNG collects an osc ring output bit every TRNG_SAMPLE_CNT clock cycles,
 * a speed/quality tradeoff giving a FIPS 140-2 quality of ~900/1024
 * (the value used by the Linux driver).
 */
#define TRNG_SAMPLE_CNT			1000
#define TRNG_MAX_BYTE			32

#define TRNG_POLL_PERIOD_US		100
#define TRNG_POLL_TIMEOUT_US		10000
#define TRNG_READ_RETRIES		3

/*
 * Gather 48 bytes per 256 bits of required entropy, assuming the same
 * conservative SP 800-90B worst-case estimate as on the RK3588 TRNG
 * (6.6556 bits/byte); the measured RK3568 quality of ~900/1024
 * (~7 bits/byte) is above that.
 */
#define TRNG_ENTROPY_256		48

/* TRNG_S clock gates and soft reset in the secure CRU (TRM Part1, CRU_S) */
#define SCRU_GATE_CON00			0x0180
#define TRNG_S_GATE_CLK			BIT(7)
#define TRNG_S_GATE_HCLK		BIT(6)
#define SCRU_GATE_CON01			0x0184
#define TRNG_GATE_CLK			BIT(11)
#define TRNG_GATE_PCLK			BIT(10)
#define SCRU_SOFTRST_CON02		0x0208
#define TRNG_S_SOFTRST_RSTN		BIT(11)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TRNG_S_BASE, TRNG_S_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SCRU_BASE, SCRU_SIZE);

static struct mutex trng_mutex = MUTEX_INITIALIZER;
static bool trng_ready;

static void trng_write_ctl(vaddr_t base, uint32_t val, uint32_t mask)
{
	io_write32(base + TRNG_RNG_CTL, SHIFT_U32(mask, 16) | val);
}

static void trng_enable_clocks(void)
{
	vaddr_t scru_base = (vaddr_t)phys_to_virt_io(SCRU_BASE, SCRU_SIZE);

	if (!scru_base)
		panic("SCRU not mapped");

	io_write32(scru_base + SCRU_GATE_CON00,
		   SHIFT_U32(TRNG_S_GATE_CLK | TRNG_S_GATE_HCLK, 16));
	io_write32(scru_base + SCRU_GATE_CON01,
		   SHIFT_U32(TRNG_GATE_CLK | TRNG_GATE_PCLK, 16));
}

static void trng_init(vaddr_t base)
{
	vaddr_t scru_base = (vaddr_t)phys_to_virt_io(SCRU_BASE, SCRU_SIZE);

	io_write32(scru_base + SCRU_SOFTRST_CON02,
		   SHIFT_U32(TRNG_S_SOFTRST_RSTN, 16) | TRNG_S_SOFTRST_RSTN);
	udelay(2);
	io_write32(scru_base + SCRU_SOFTRST_CON02,
		   SHIFT_U32(TRNG_S_SOFTRST_RSTN, 16));

	io_write32(base + TRNG_RNG_SAMPLE_CNT, TRNG_SAMPLE_CNT);

	trng_write_ctl(base, TRNG_RNG_CTL_LEN_256_BIT |
		       TRNG_RNG_CTL_OSC_RING_SPEED_0 | TRNG_RNG_CTL_ENABLE,
		       TRNG_RNG_CTL_MASK);

	trng_ready = true;
}

static TEE_Result trng_read_block(vaddr_t base, uint8_t *out, size_t copy_len)
{
	uint32_t rnd[TRNG_MAX_BYTE / sizeof(uint32_t)] = { };
	unsigned int retry = 0;
	uint32_t val = 0;
	size_t i = 0;

	for (retry = 0; retry < TRNG_READ_RETRIES; retry++) {
		trng_write_ctl(base, TRNG_RNG_CTL_START, TRNG_RNG_CTL_START);

		if (!IO_READ32_POLL_TIMEOUT(base + TRNG_RNG_CTL, val,
					    !(val & TRNG_RNG_CTL_START),
					    TRNG_POLL_PERIOD_US,
					    TRNG_POLL_TIMEOUT_US))
			break;

		/* Transient stall: re-init and try again */
		trng_init(base);
	}
	if (retry == TRNG_READ_RETRIES)
		return TEE_ERROR_BUSY;

	for (i = 0; i < ARRAY_SIZE(rnd); i++)
		rnd[i] = io_read32(base + TRNG_RNG_DOUT + i * sizeof(uint32_t));

	memcpy(out, rnd, copy_len);
	memzero_explicit(rnd, sizeof(rnd));

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(TRNG_S_BASE, TRNG_S_SIZE);
	uint8_t *out = buf;
	size_t remaining = blen;
	TEE_Result res = TEE_SUCCESS;

	if (!base)
		panic("TRNG_S not mapped");

	mutex_lock(&trng_mutex);

	/* Clocks live in the secure CRU, but re-assert them defensively */
	trng_enable_clocks();

	if (!trng_ready ||
	    !(io_read32(base + TRNG_RNG_CTL) & TRNG_RNG_CTL_ENABLE) ||
	    io_read32(base + TRNG_RNG_SAMPLE_CNT) != TRNG_SAMPLE_CNT)
		trng_init(base);

	while (remaining) {
		size_t copy_len = MIN(remaining, (size_t)TRNG_MAX_BYTE);

		res = trng_read_block(base, out, copy_len);
		if (res)
			break;

		out += copy_len;
		remaining -= copy_len;
	}

	mutex_unlock(&trng_mutex);

	return res;
}

static bool buf_is_zero(const void *buf, size_t len)
{
	const uint8_t *b = buf;
	size_t i = 0;
	uint8_t acc = 0;

	for (i = 0; i < len; i++)
		acc |= b[i];

	return !acc;
}

#ifdef CFG_WITH_SOFTWARE_PRNG
void plat_init_soft_prng(void)
{
	uint8_t seed[TRNG_ENTROPY_256] = { };
	TEE_Result res = TEE_SUCCESS;

	res = hw_get_random_bytes(seed, sizeof(seed));
	if (res)
		panic("Failed to get TRNG seed data");

	if (buf_is_zero(seed, sizeof(seed)))
		panic("TRNG returned all-zero seed data");

	res = crypto_rng_init(seed, sizeof(seed));
	if (res)
		panic("Failed to initialize RNG with seed");

	memzero_explicit(seed, sizeof(seed));
}
#endif /* CFG_WITH_SOFTWARE_PRNG */
