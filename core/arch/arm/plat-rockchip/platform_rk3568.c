// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Daniel Golle <daniel@makrotopia.org>
 */

#include <assert.h>
#include <common.h>
#include <crypto/crypto.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
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

/*
 * Secure instance of the SBPI/USER-mode OTP controller (same IP as the
 * non-secure one driven by Linux nvmem rockchip-otp.c, secure clocking
 * and SGRF handling as in TF-A rk3568/drivers/otp/otp.c). The secure
 * region covers halfword addresses 0x000-0x1bf; USER-mode addresses are
 * relative to the controller's own window.
 */
#define OTPC_SBPI_CTRL			0x0020
#define OTPC_SBPI_CMD_VALID_PRE		0x0024
#define OTPC_SBPI_CS_VALID_PRE		0x0028
#define OTPC_SBPI_STATUS		0x002c
#define OTPC_USER_CTRL			0x0100
#define OTPC_USER_ADDR			0x0104
#define OTPC_USER_ENABLE		0x0108
#define OTPC_USER_QP			0x0120
#define OTPC_USER_Q			0x0124
#define OTPC_INT_STATUS			0x0304
#define OTPC_SBPI_CMD_OFFSET(n)		(0x1000 + (n) * 4)

#define OTPC_USE_USER			BIT(0)
#define OTPC_USER_FSM_ENABLE		BIT(0)
#define OTPC_SBPI_DONE			BIT(1)
#define OTPC_USER_DONE			BIT(2)
#define OTPC_SBPI_STATUS_BUSY		BIT(4)

#define SBPI_DAP_ADDR			0x02
#define SBPI_DAP_PROG_ADDR		0x3a
#define SBPI_DAP_ADDR_SHIFT		8
#define SBPI_DAP_CMD_WRF		0xc0
#define SBPI_DAP_REG_ECC		0x3a
#define SBPI_ECC_ENABLE			0x00
#define SBPI_ECC_DISABLE		0x09
#define SBPI_ENABLE			BIT(0)
#define SBPI_CS_AUTO			BIT(2)

#define OTP_S_HALFWORDS			448
#define OTP_WRITE_MAX			16

#define OTP_POLL_PERIOD_US		1
#define OTP_POLL_TIMEOUT_US		10000
#define OTP_PROG_IDLE_TIMEOUT_US	100001
#define OTP_PROG_BUSY_TIMEOUT_US	20001

/* pclk_otpphy gate and OTP PHY soft reset (Linux clk-rk3568.c) */
#define OTPPHY_CLKGATE_CON		34
#define OTPPHY_CLKGATE_PCLK		BIT(13)
#define OTPPHY_SOFTRST_CON		28
#define OTPPHY_SOFTRST_RSTN		BIT(15)

/* Secure OTP clock gates and SGRF control (TF-A rk3568 otp.c) */
#define OTP_S_PCLK_EN			BIT(5)
#define OTP_S_SBPI_EN			BIT(6)
#define OTP_S_USER_EN			BIT(7)
#define SGRF_SOC_CON2			0x0008
#define SGRF_CON_OTP_SECURE		BIT(1)
#define SGRF_CON_OTP_CKE		BIT(2)

/* CRU register bases (Linux clk-rk3568.c) */
#define CRU_CLKGATE_CON(i)		(0x300 + (i) * 4)
#define CRU_SOFTRST_CON(i)		(0x400 + (i) * 4)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_S_BASE, OTP_S_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CRU_BASE, CRU_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SGRF_BASE, SGRF_SIZE);

static struct mutex otp_mutex = MUTEX_INITIALIZER;

static void otp_enable_clocks(void)
{
	vaddr_t cru_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);
	vaddr_t scru_base = (vaddr_t)phys_to_virt_io(SCRU_BASE, SCRU_SIZE);

	if (!cru_base || !scru_base)
		panic("CRU/SCRU not mapped");

	io_write32(cru_base + CRU_CLKGATE_CON(OTPPHY_CLKGATE_CON),
		   SHIFT_U32(OTPPHY_CLKGATE_PCLK, 16));
	io_write32(scru_base + SCRU_GATE_CON01,
		   SHIFT_U32(OTP_S_PCLK_EN | OTP_S_SBPI_EN | OTP_S_USER_EN,
			     16));
}

static void otp_phy_reset(void)
{
	vaddr_t cru_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	io_write32(cru_base + CRU_SOFTRST_CON(OTPPHY_SOFTRST_CON),
		   SHIFT_U32(OTPPHY_SOFTRST_RSTN, 16) | OTPPHY_SOFTRST_RSTN);
	udelay(2);
	io_write32(cru_base + CRU_SOFTRST_CON(OTPPHY_SOFTRST_CON),
		   SHIFT_U32(OTPPHY_SOFTRST_RSTN, 16));
	udelay(1);
}

static void otp_sgrf_secure(bool secure)
{
	vaddr_t sgrf_base = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);

	if (!sgrf_base)
		panic("SGRF not mapped");

	if (secure)
		io_write32(sgrf_base + SGRF_SOC_CON2,
			   SHIFT_U32(SGRF_CON_OTP_SECURE | SGRF_CON_OTP_CKE,
				     16) |
			   SGRF_CON_OTP_SECURE | SGRF_CON_OTP_CKE);
	else
		io_write32(sgrf_base + SGRF_SOC_CON2,
			   SHIFT_U32(SGRF_CON_OTP_SECURE, 16));
}

static TEE_Result otp_wait_status(vaddr_t base, uint32_t flag)
{
	uint32_t status = 0;

	if (IO_READ32_POLL_TIMEOUT(base + OTPC_INT_STATUS, status,
				   status & flag, OTP_POLL_PERIOD_US,
				   OTP_POLL_TIMEOUT_US))
		return TEE_ERROR_BUSY;

	io_write32(base + OTPC_INT_STATUS, SHIFT_U32(0xffff, 16) | flag);

	return TEE_SUCCESS;
}

static void otp_sbpi_dev_id(vaddr_t base, uint8_t id)
{
	io_write32(base + OTPC_SBPI_CTRL,
		   SHIFT_U32(0xff, 16 + SBPI_DAP_ADDR_SHIFT) |
		   SHIFT_U32(id, SBPI_DAP_ADDR_SHIFT));
}

static TEE_Result otp_sbpi_run(vaddr_t base, const uint8_t *cmd, size_t n)
{
	size_t i = 0;

	io_write32(base + OTPC_SBPI_CMD_VALID_PRE,
		   SHIFT_U32(0xffff, 16) | (n - 1));
	for (i = 0; i < n; i++)
		io_write32(base + OTPC_SBPI_CMD_OFFSET(i), cmd[i]);
	io_write32(base + OTPC_SBPI_CTRL,
		   SHIFT_U32(SBPI_ENABLE, 16) | SBPI_ENABLE);

	return otp_wait_status(base, OTPC_SBPI_DONE);
}

static TEE_Result otp_ecc_enable(vaddr_t base, bool enable)
{
	uint8_t cmd[2] = { SBPI_DAP_CMD_WRF | SBPI_DAP_REG_ECC,
			   SBPI_ECC_DISABLE };

	if (enable)
		cmd[1] = SBPI_ECC_ENABLE;

	otp_sbpi_dev_id(base, SBPI_DAP_ADDR);

	return otp_sbpi_run(base, cmd, sizeof(cmd));
}

/*
 * The secure region is read and written with ECC disabled, as the vendor
 * secure OTP driver does (unlike the ECC-covered non-secure region).
 * Lock-free core: caller holds otp_mutex and has enabled the clocks.
 */
static TEE_Result otp_read_locked(vaddr_t base, uint16_t *value,
				  uint32_t addr, uint32_t count)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t i = 0;

	otp_sgrf_secure(true);
	otp_phy_reset();

	res = otp_ecc_enable(base, false);
	if (res)
		goto out;

	io_write32(base + OTPC_USER_CTRL,
		   SHIFT_U32(OTPC_USE_USER, 16) | OTPC_USE_USER);
	udelay(5);

	for (i = 0; i < count; i++) {
		io_write32(base + OTPC_USER_ADDR,
			   SHIFT_U32(0xffff, 16) | (addr + i));
		io_write32(base + OTPC_USER_ENABLE,
			   SHIFT_U32(OTPC_USER_FSM_ENABLE, 16) |
			   OTPC_USER_FSM_ENABLE);

		res = otp_wait_status(base, OTPC_USER_DONE);
		if (res)
			break;

		value[i] = io_read32(base + OTPC_USER_Q);
	}

	io_write32(base + OTPC_USER_CTRL, SHIFT_U32(OTPC_USE_USER, 16));

out:
	otp_sgrf_secure(false);

	return res;
}

static TEE_Result otp_read_secure(uint16_t *value, uint32_t addr,
				  uint32_t count)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(OTP_S_BASE, OTP_S_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!base)
		panic("OTP_S not mapped");

	if (!value || !count || addr >= OTP_S_HALFWORDS ||
	    count > OTP_S_HALFWORDS - addr)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&otp_mutex);
	otp_enable_clocks();
	res = otp_read_locked(base, value, addr, count);
	mutex_unlock(&otp_mutex);

	return res;
}

/*
 * Halfword addresses the vendor secure OTP driver permits programming;
 * everything else (BootROM device data, secure-boot cells outside the
 * whitelisted windows) is refused.
 */
static bool otp_addr_writable(uint32_t addr)
{
	return addr == 64 || (addr >= 72 && addr <= 102) ||
	       (addr >= 112 && addr <= 115) ||
	       (addr >= 229 && addr < OTP_S_HALFWORDS);
}

static TEE_Result otp_wait_prog(vaddr_t base, bool busy, uint32_t timeout_us)
{
	uint32_t status = 0;

	if (IO_READ32_POLL_TIMEOUT(base + OTPC_SBPI_STATUS, status,
				   busy == !!(status & OTPC_SBPI_STATUS_BUSY),
				   OTP_POLL_PERIOD_US, timeout_us))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

/*
 * Program one halfword, SBPI transaction sequence as in the vendor
 * U-Boot rk3568_secure_otp_write_2_bytes_noecc(). OTP bits only program
 * 0 -> 1; an all-zero halfword needs no programming.
 */
static TEE_Result otp_program_halfword(vaddr_t base, uint32_t addr,
				       uint16_t data)
{
	const uint8_t t0[3] = { 0xfc, 0x00, 0x00 };
	const uint8_t t1[15] = { 0xf0, 0x01, 0x7a, 0x25, 0x00, 0x00, 0x00,
				 0x1f, 0x0b, 0x08, 0x00, 0x00, 0x00,
				 addr & 0xff, (addr >> 8) & 0xff };
	const uint8_t t2[2] = { 0xfa, SBPI_ECC_DISABLE };
	const uint8_t t3[15] = { 0xf0, 0x01, 0x7a, 0x15, 0xdc, 0x92, 0x79,
				 0x81, 0x7e, 0x21, 0x11, 0x9d, 0x02, 0x00,
				 0x40 };
	const uint8_t t4[3] = { 0xfc, 0x0a, 0x70 };
	const uint8_t t5[3] = { 0xc0, data & 0xff, (data >> 8) & 0xff };
	const uint8_t t6[2] = { 0xe0, 0x00 };
	const uint8_t t7[2] = { 0xff, 0x0a };
	const uint8_t t8[2] = { 0x01, 0xbf };
	const uint8_t t9[2] = { 0x02, 0xbf };
	const uint8_t t10[2] = { 0x02, 0x80 };
	const uint8_t t11[2] = { 0xa0, 0x00 };
	TEE_Result res = TEE_SUCCESS;

	if (!data)
		return TEE_SUCCESS;

	otp_sgrf_secure(true);
	otp_phy_reset();

	io_write32(base + OTPC_USER_CTRL, SHIFT_U32(OTPC_USE_USER, 16));
	io_write32(base + OTPC_SBPI_CTRL,
		   SHIFT_U32(SBPI_CS_AUTO, 16) | SBPI_CS_AUTO);
	io_write32(base + OTPC_SBPI_CS_VALID_PRE, SHIFT_U32(0xffff, 16));
	otp_sbpi_dev_id(base, SBPI_DAP_ADDR);
	res = otp_sbpi_run(base, t0, sizeof(t0));
	if (res)
		return res;

	res = otp_sbpi_run(base, t1, sizeof(t1));
	if (res)
		return res;

	res = otp_sbpi_run(base, t2, sizeof(t2));
	if (res)
		return res;

	otp_sbpi_dev_id(base, SBPI_DAP_PROG_ADDR);
	res = otp_sbpi_run(base, t3, sizeof(t3));
	if (res)
		return res;

	res = otp_sbpi_run(base, t4, sizeof(t4));
	if (res)
		return res;

	otp_sbpi_dev_id(base, SBPI_DAP_ADDR);
	res = otp_sbpi_run(base, t5, sizeof(t5));
	if (res)
		return res;

	res = otp_sbpi_run(base, t6, sizeof(t6));
	if (res)
		return res;

	otp_sbpi_dev_id(base, SBPI_DAP_PROG_ADDR);
	res = otp_sbpi_run(base, t7, sizeof(t7));
	if (res)
		return res;

	res = otp_sbpi_run(base, t8, sizeof(t8));
	if (res)
		return res;
	res = otp_wait_prog(base, false, OTP_PROG_IDLE_TIMEOUT_US);
	if (res)
		return res;

	res = otp_sbpi_run(base, t9, sizeof(t9));
	if (res)
		return res;
	res = otp_wait_prog(base, true, OTP_PROG_BUSY_TIMEOUT_US);
	if (res)
		return res;

	io_write32(base + OTPC_INT_STATUS,
		   SHIFT_U32(0xffff, 16) | OTPC_SBPI_DONE | BIT(0));
	otp_sbpi_dev_id(base, SBPI_DAP_ADDR);
	res = otp_sbpi_run(base, t10, sizeof(t10));
	if (res)
		return res;

	res = otp_sbpi_run(base, t11, sizeof(t11));
	if (res)
		return res;

	return otp_sbpi_run(base, t2, sizeof(t2));
}

static TEE_Result otp_write_secure(const uint16_t *value, uint32_t addr,
				   uint32_t count)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(OTP_S_BASE, OTP_S_SIZE);
	uint16_t current[OTP_WRITE_MAX] = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t i = 0;

	if (!base)
		panic("OTP_S not mapped");

	if (!value || !count || addr >= OTP_S_HALFWORDS ||
	    count > OTP_S_HALFWORDS - addr)
		return TEE_ERROR_BAD_PARAMETERS;

	if (count > ARRAY_SIZE(current))
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < count; i++)
		if (!otp_addr_writable(addr + i))
			return TEE_ERROR_ACCESS_DENIED;

	mutex_lock(&otp_mutex);

	otp_enable_clocks();

	/*
	 * OTP cells only program 0 -> 1, so writing over a non-blank cell
	 * would OR bits and corrupt it. Refuse unless the target is blank,
	 * as the vendor driver does.
	 */
	res = otp_read_locked(base, current, addr, count);
	if (res)
		goto out;

	for (i = 0; i < count; i++) {
		if (current[i]) {
			res = TEE_ERROR_ACCESS_DENIED;
			goto out;
		}
	}

	for (i = 0; i < count; i++) {
		res = otp_program_halfword(base, addr + i, value[i]);
		if (res)
			break;
	}

out:
	otp_sgrf_secure(false);
	memzero_explicit(current, sizeof(current));
	mutex_unlock(&otp_mutex);

	return res;
}

static struct mutex huk_mutex = MUTEX_INITIALIZER;

/* Cache the HUK in memory */
static struct tee_hw_unique_key *huk;

/*
 * Condition raw TRNG output down to the key length with SHA-256 so the
 * 128-bit HUK carries a full 128 bits of entropy even under the
 * conservative 6.6556 bits/byte worst-case estimate for this TRNG.
 */
static TEE_Result generate_huk(struct tee_hw_unique_key *hwkey)
{
	uint8_t raw[2 * HW_UNIQUE_KEY_LENGTH] = { };
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;

	static_assert(HW_UNIQUE_KEY_LENGTH <= TEE_SHA256_HASH_SIZE);

	res = hw_get_random_bytes(raw, sizeof(raw));
	if (res)
		goto out;

	/* All-zero raw output indicates TRNG failure */
	if (buf_is_zero(raw, sizeof(raw))) {
		res = TEE_ERROR_NO_DATA;
		goto out;
	}

	res = tee_hash_createdigest(TEE_ALG_SHA256, raw, sizeof(raw),
				    digest, sizeof(digest));
	if (res)
		goto out;

	memcpy(hwkey->data, digest, HW_UNIQUE_KEY_LENGTH);

out:
	memzero_explicit(raw, sizeof(raw));
	memzero_explicit(digest, sizeof(digest));

	return res;
}

static TEE_Result read_huk(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;
	uint16_t buffer[ROCKCHIP_OTP_HUK_SIZE] = { };
	uint16_t marker = 0;

	static_assert(sizeof(buffer) == sizeof(hwkey->data));

	res = otp_read_secure(buffer, ROCKCHIP_OTP_HUK_ADDR,
			      ROCKCHIP_OTP_HUK_SIZE);
	if (res)
		goto out;
	res = otp_read_secure(&marker, ROCKCHIP_OTP_HUK_MARKER_ADDR, 1);
	if (res)
		goto out;

	if (marker == ROCKCHIP_OTP_HUK_MARKER) {
		memcpy(hwkey->data, buffer, HW_UNIQUE_KEY_LENGTH);
		res = TEE_SUCCESS;
	} else if (!marker && buf_is_zero(buffer, sizeof(buffer))) {
		/* Blank key and marker: no HUK provisioned yet */
		res = TEE_ERROR_NO_DATA;
	} else {
		/*
		 * Non-blank key without a valid marker means an interrupted
		 * or tampered burn. Fail closed rather than use a partial key.
		 */
		EMSG("HUK OTP present but marker invalid (0x%04"PRIx16")",
		     marker);
		res = TEE_ERROR_SECURITY;
	}

out:
	memzero_explicit(buffer, sizeof(buffer));

	return res;
}

static TEE_Result persist_huk(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;
	uint16_t buffer[ROCKCHIP_OTP_HUK_SIZE] = { };
	uint16_t verify[ROCKCHIP_OTP_HUK_SIZE] = { };
	uint16_t marker = ROCKCHIP_OTP_HUK_MARKER;

	static_assert(sizeof(buffer) == sizeof(hwkey->data));

	memcpy(buffer, hwkey->data, HW_UNIQUE_KEY_LENGTH);

	res = otp_write_secure(buffer, ROCKCHIP_OTP_HUK_ADDR,
			       ROCKCHIP_OTP_HUK_SIZE);
	if (res)
		goto out;

	/* Read back to catch a partial or failed burn before the marker */
	res = otp_read_secure(verify, ROCKCHIP_OTP_HUK_ADDR,
			      ROCKCHIP_OTP_HUK_SIZE);
	if (res)
		goto out;

	if (consttime_memcmp(buffer, verify, sizeof(buffer))) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Commit the marker only once the key is fully written and verified */
	res = otp_write_secure(&marker, ROCKCHIP_OTP_HUK_MARKER_ADDR, 1);

out:
	memzero_explicit(buffer, sizeof(buffer));
	memzero_explicit(verify, sizeof(verify));

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&huk_mutex);

	if (huk)
		goto out;

	huk = malloc(sizeof(*huk));
	if (!huk) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_huk(huk);
	if (res != TEE_ERROR_NO_DATA)
		goto out;

	/* No HUK provisioned yet: generate one and persist it in the OTP */
	res = generate_huk(huk);
	if (res)
		goto out;
	res = persist_huk(huk);

out:
	if (!res) {
		memcpy(hwkey->data, huk->data, HW_UNIQUE_KEY_LENGTH);
	} else if (huk) {
		free_wipe(huk);
		huk = NULL;
	}

	mutex_unlock(&huk_mutex);

	return res;
}
