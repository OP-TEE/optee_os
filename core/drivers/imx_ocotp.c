// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */
#include <arm.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <imx.h>
#include <io.h>
#include <drivers/imx_ocotp.h>
#include <kernel/delay.h>
#include <kernel/delay_arch.h>
#include <kernel/tee_common_otp.h>
#include <util.h>

#define OCOTP_CTRL			0x0
#define OCOTP_CTRL_SET			0x4
#define OCOTP_CTRL_CLR			0x8
#define OCOTP_TIMING			0x10
#define OCOTP_DATA			0x20

#define OCOTP_CTRL_WR_UNLOCK_KEY	0x3E77

#define OCOTP_TIMING_WAIT		GENMASK_32(27, 22)
#define OCOTP_TIMING_STROBE_READ	GENMASK_32(21, 16)
#define OCOTP_TIMING_RELAX		GENMASK_32(15, 12)
#define OCOTP_TIMING_STROBE_PROG	GENMASK_32(11, 0)

#define OCOTP_CTRL_WR_UNLOCK		GENMASK_32(31, 16)
#if defined(CFG_MX8MP)
#define OCOTP_CTRL_RELOAD_SHADOWS	BIT32(11)
#define OCOTP_CTRL_ERROR		BIT32(10)
#define OCOTP_CTRL_BUSY			BIT32(9)
#define OCOTP_CTRL_ADDR			GENMASK_32(8, 0)
#else
#define OCOTP_CTRL_RELOAD_SHADOWS	BIT32(10)
#define OCOTP_CTRL_ERROR		BIT32(9)
#define OCOTP_CTRL_BUSY			BIT32(8)
#define OCOTP_CTRL_ADDR			GENMASK_32(7, 0)
#endif

#if defined(CFG_MX6) || defined(CFG_MX7ULP)
#define OCOTP_SHADOW_OFFSET(_b, _w)	((_b) * (0x80) + (_w) * (0x10) + 0x400)
#else
#define OCOTP_SHADOW_OFFSET(_b, _w)	((_b) * (0x40) + (_w) * (0x10) + 0x400)
#endif

/* Shadow reload needs more time if eFuses where written prior */
#define OCOTP_OP_BUSY_TIMEOUT_US	1000

#define OCOTP_ADDR(_b, _w)		(((_b) * (0x40) + (_w) * (0x10)) / 0x10)

#define TIMING_STROBE_PROG_US		10	/* Min time to blow a fuse */
#define TIMING_STROBE_READ_NS		37	/* Min time before read */
#define TIMING_RELAX_NS			17

struct ocotp_instance {
	unsigned char nb_banks;
	unsigned char nb_words;
	TEE_Result (*get_die_id)(uint64_t *ret_uid);
	TEE_Result (*write_fuse)(unsigned int bank, unsigned int word,
				 uint32_t val);
};

static vaddr_t g_base_addr;
static struct mutex fuse_read = MUTEX_INITIALIZER;
static const struct ocotp_instance *g_ocotp;

#if defined(CFG_MX6)
static void ocotp_clock_enable(void)
{
	vaddr_t va = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC, CCM_SIZE);

	io_setbits32(va + CCM_CCGR2, BM_CCM_CCGR2_OCOTP_CTRL);
}
#elif defined(CFG_MX7)
static void ocotp_clock_enable(void)
{
	vaddr_t va = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC, CCM_SIZE);

	io_setbits32(va + CCM_CCGRx_SET(CCM_CLOCK_DOMAIN_OCOTP),
		     CCM_CCGRx_ALWAYS_ON(0));
}
#elif defined(CFG_MX8M)
static void ocotp_clock_enable(void)
{
	vaddr_t va = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC, CCM_SIZE);

	io_setbits32(va + CCM_CCGRx_SET(CCM_CCRG_OCOTP),
		     CCM_CCGRx_ALWAYS_ON(0));
}
#elif defined(CFG_MX7ULP)
/* The i.MX7ULP has the OCOTP always powered on */
static inline void ocotp_clock_enable(void) { }
#else
#error "Platform not supported"
#endif

#if defined(CFG_CORE_HAS_GENERIC_TIMER)
static TEE_Result ocotp_ctrl_wait_for(uint32_t mask)
{
	uint32_t val = 0;

	assert(g_base_addr);
	if (IO_READ32_POLL_TIMEOUT(g_base_addr + OCOTP_CTRL, val,
				   !(val & mask), 0, OCOTP_OP_BUSY_TIMEOUT_US))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}
#else
static TEE_Result ocotp_ctrl_wait_for(uint32_t mask)
{
	uint32_t delay_us = OCOTP_OP_BUSY_TIMEOUT_US;
	uint32_t reg = 0;

	assert(g_base_addr);
	for (; delay_us > 0; delay_us--) {
		reg = io_read32(g_base_addr + OCOTP_CTRL) & mask;
		if (!reg)
			return TEE_SUCCESS;
		udelay(1);
		isb();
	}

	return TEE_ERROR_BUSY;
}
#endif

TEE_Result imx_ocotp_read(unsigned int bank, unsigned int word, uint32_t *val)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!val)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(g_base_addr && g_ocotp);

	if (bank > g_ocotp->nb_banks || word > g_ocotp->nb_words)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&fuse_read);

	ocotp_clock_enable();

	/* Clear error bit */
	io_write32(g_base_addr + OCOTP_CTRL_CLR, OCOTP_CTRL_ERROR);

	/* Wait for busy flag to be cleared */
	ret = ocotp_ctrl_wait_for(OCOTP_CTRL_BUSY);
	if (ret) {
		EMSG("OCOTP is busy");
		goto out;
	}

	/* Read shadow register */
	*val = io_read32(g_base_addr + OCOTP_SHADOW_OFFSET(bank, word));

	DMSG("OCOTP Bank %d Word %d Fuse 0x%" PRIx32, bank, word, *val);
out:
	mutex_unlock(&fuse_read);

	return ret;
}

TEE_Result imx_ocotp_write(unsigned int bank, unsigned int word, uint32_t val)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!val)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(g_base_addr && g_ocotp);

	if (bank > g_ocotp->nb_banks || word > g_ocotp->nb_words)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_ocotp->write_fuse)
		return TEE_ERROR_NOT_IMPLEMENTED;

	mutex_lock(&fuse_read);

	ocotp_clock_enable();

	/* Clear error bit */
	io_write32(g_base_addr + OCOTP_CTRL_CLR, OCOTP_CTRL_ERROR);

	/* Wait for busy flag to be cleared */
	ret = ocotp_ctrl_wait_for(OCOTP_CTRL_BUSY);
	if (ret) {
		EMSG("OCOTP is busy");
		goto out;
	}

	ret = g_ocotp->write_fuse(bank, word, val);
	if (ret) {
		EMSG("OCOTP write fuse failed");
		goto out;
	}

	io_write32(g_base_addr + OCOTP_CTRL_SET, OCOTP_CTRL_RELOAD_SHADOWS);

	ret = ocotp_ctrl_wait_for(OCOTP_CTRL_BUSY);
	if (ret) {
		EMSG("OCOTP is busy");
		goto out;
	}

	DMSG("OCOTP Bank %d Word %d Fuse 0x%" PRIx32, bank, word, val);
out:
	mutex_unlock(&fuse_read);

	return ret;
}

static TEE_Result ocotp_mx8m_set_timing(void)
{
	uint32_t strobe_read = 0;
	uint32_t strobe_prog = 0;
	uint32_t clk_rate = 0;
	uint32_t timing = 0;
	uint32_t relax = 0;

	/* Assume the IPG_ROOT clock is running at 66.67 MHz */
	clk_rate = 66666667;

	relax = DIV_ROUND_UP(clk_rate * TIMING_RELAX_NS, 1000000000) - 1;

	strobe_read = DIV_ROUND_UP(clk_rate * TIMING_STROBE_READ_NS,
				   1000000000);
	strobe_read += 2 * (relax + 1) - 1;
	strobe_prog = UDIV_ROUND_NEAREST(clk_rate * TIMING_STROBE_PROG_US,
					 1000000);
	strobe_prog += 2 * (relax + 1) - 1;

	timing = io_read32(g_base_addr + OCOTP_TIMING) & OCOTP_TIMING_WAIT;
	timing = set_field_u32(timing, OCOTP_TIMING_RELAX, relax);
	timing = set_field_u32(timing, OCOTP_TIMING_STROBE_READ, strobe_read);
	timing = set_field_u32(timing, OCOTP_TIMING_STROBE_PROG, strobe_prog);

	io_write32(g_base_addr + OCOTP_TIMING, timing);

	return ocotp_ctrl_wait_for(OCOTP_CTRL_BUSY);
}

static TEE_Result ocotp_mx8m_write_fuse(unsigned int bank, unsigned int word,
					uint32_t val)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t reg = 0;

	ret = ocotp_mx8m_set_timing();
	if (ret) {
		EMSG("OCOTP set_timing failed");
		return ret;
	}

	/* Control register */
	reg = io_read32(g_base_addr + OCOTP_CTRL);
	reg &= ~OCOTP_CTRL_ADDR;
	reg = set_field_u32(reg, OCOTP_CTRL_ADDR, OCOTP_ADDR(bank, word));
	reg = set_field_u32(reg, OCOTP_CTRL_WR_UNLOCK,
			    OCOTP_CTRL_WR_UNLOCK_KEY);
	io_write32(g_base_addr + OCOTP_CTRL, reg);

	/* Clear error bit */
	io_write32(g_base_addr + OCOTP_CTRL_CLR, OCOTP_CTRL_ERROR);

	io_write32(g_base_addr + OCOTP_DATA, val);
	ret = ocotp_ctrl_wait_for(OCOTP_CTRL_BUSY);
	if (ret) {
		EMSG("OCOTP write fuse-val failed");
		return ret;
	}

	/*
	 * Write postamble (TRM):
	 * Due to internal electrical characteristics of the OTP during writes,
	 * all OTP operations following a write must be separated by 2 us after
	 * the clearing of HW_OCOTP_CTRL_BUSY following the write. This
	 * guarantees programming voltages on-chip to reach a steady state when
	 * exiting a write sequence. This includes reads, shadow reloads, or
	 * other writes.
	 */
	udelay(2);

	if (io_read32(g_base_addr + OCOTP_CTRL) & OCOTP_CTRL_ERROR) {
		EMSG("OCOTP bad write status");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result ocotp_get_die_id_mx7ulp(uint64_t *ret_uid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;
	uint64_t uid = 0;

	res = imx_ocotp_read(1, 6, &val);
	if (res)
		goto out;
	uid = val & GENMASK_32(15, 0);

	res = imx_ocotp_read(1, 5, &val);
	if (res)
		goto out;
	uid = SHIFT_U64(uid, 16) | (val & GENMASK_32(15, 0));

	res = imx_ocotp_read(1, 4, &val);
	if (res)
		goto out;
	uid = SHIFT_U64(uid, 16) | (val & GENMASK_32(15, 0));

	res = imx_ocotp_read(1, 3, &val);
	if (res)
		goto out;
	uid = SHIFT_U64(uid, 16) | (val & GENMASK_32(15, 0));

out:
	if (res == TEE_SUCCESS)
		*ret_uid = uid;

	return res;
}

static TEE_Result ocotp_get_die_id_mx(uint64_t *ret_uid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;
	uint64_t uid = 0;

	res = imx_ocotp_read(0, 2, &val);
	if (res)
		goto out;
	uid = val;

	res = imx_ocotp_read(0, 1, &val);
	if (res)
		goto out;
	uid = SHIFT_U64(uid, 32) | val;

out:
	if (res == TEE_SUCCESS)
		*ret_uid = uid;

	return res;
}

static const struct ocotp_instance ocotp_imx6q = {
	.nb_banks = 16,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx6sl = {
	.nb_banks = 8,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx6sll = {
	.nb_banks = 16,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx6sx = {
	.nb_banks = 16,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx6ul = {
	.nb_banks = 16,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx6ull = {
	.nb_banks = 8,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx7d = {
	.nb_banks = 8,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
};

static const struct ocotp_instance ocotp_imx7ulp = {
	.nb_banks = 32,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx7ulp,
};

static const struct ocotp_instance ocotp_imx8m = {
	.nb_banks = 32,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
	.write_fuse = ocotp_mx8m_write_fuse,
};

static const struct ocotp_instance ocotp_imx8mp = {
	.nb_banks = 48,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
	.write_fuse = ocotp_mx8m_write_fuse,
};

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	size_t max_size_uid = IMX_UID_SIZE;
	uint64_t uid = 0;

	assert(buffer);
	assert(g_base_addr && g_ocotp);

	if (g_ocotp->get_die_id(&uid))
		goto err;

	memcpy(buffer, &uid, MIN(max_size_uid, len));
	return 0;

err:
	EMSG("Error while getting die ID");
	return -1;
}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, OCOTP_BASE, CORE_MMU_PGDIR_SIZE);
static TEE_Result imx_ocotp_init(void)
{
	g_base_addr = core_mmu_get_va(OCOTP_BASE, MEM_AREA_IO_SEC, OCOTP_SIZE);
	if (!g_base_addr)
		return TEE_ERROR_GENERIC;

	if (soc_is_imx6sdl() || soc_is_imx6dq() || soc_is_imx6dqp()) {
		g_ocotp = &ocotp_imx6q;
	} else if (soc_is_imx6sl()) {
		g_ocotp = &ocotp_imx6sl;
	} else if (soc_is_imx6sll()) {
		g_ocotp = &ocotp_imx6sll;
	} else if (soc_is_imx6sx()) {
		g_ocotp = &ocotp_imx6sx;
	} else if (soc_is_imx6ul()) {
		g_ocotp = &ocotp_imx6ul;
	} else if (soc_is_imx6ull()) {
		g_ocotp = &ocotp_imx6ull;
	} else if (soc_is_imx7ds()) {
		g_ocotp = &ocotp_imx7d;
	} else if (soc_is_imx7ulp()) {
		g_ocotp = &ocotp_imx7ulp;
	} else if (soc_is_imx8mm() || soc_is_imx8mn() || soc_is_imx8mq()) {
		g_ocotp = &ocotp_imx8m;
	} else if (soc_is_imx8mp()) {
		g_ocotp = &ocotp_imx8mp;
	} else {
		g_ocotp = NULL;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}
service_init(imx_ocotp_init);
