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
#include <kernel/tee_common_otp.h>

#define OCOTP_CTRL		    0x0
#define OCOTP_CTRL_ERROR	    BIT32(9)
#define OCOTP_CTRL_BUSY		    BIT32(8)

#if defined(CFG_MX6) || defined(CFG_MX7ULP)
#define OCOTP_SHADOW_OFFSET(_b, _w) ((_b) * (0x80) + (_w) * (0x10) + 0x400)
#else
#define OCOTP_SHADOW_OFFSET(_b, _w) ((_b) * (0x40) + (_w) * (0x10) + 0x400)
#endif

struct ocotp_instance {
	unsigned char nb_banks;
	unsigned char nb_words;
	TEE_Result (*get_die_id)(uint64_t *ret_uid);
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

static TEE_Result ocotp_ctrl_wait_for(uint32_t mask)
{
	unsigned int loop = 0;
	uint32_t reg = 0;

	assert(g_base_addr);

	/* 20us delay assuming the CPU clock running at 500MHz */
	for (loop = 10000; loop > 0; loop--) {
		reg = io_read32(g_base_addr + OCOTP_CTRL) & mask;
		if (!reg)
			return TEE_SUCCESS;
		dsb();
		isb();
	}

	return TEE_ERROR_BUSY;
}

TEE_Result imx_ocotp_read(unsigned int bank, unsigned int word, uint32_t *val)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!val)
		return TEE_ERROR_BAD_PARAMETERS;

	if (bank > g_ocotp->nb_banks || word > g_ocotp->nb_words)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(g_base_addr && g_ocotp);

	mutex_lock(&fuse_read);

	ocotp_clock_enable();

	/* Clear error bit */
	io_clrbits32(g_base_addr + OCOTP_CTRL, OCOTP_CTRL_ERROR);

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
};

static const struct ocotp_instance ocotp_imx8mp = {
	.nb_banks = 48,
	.nb_words = 8,
	.get_die_id = ocotp_get_die_id_mx,
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
