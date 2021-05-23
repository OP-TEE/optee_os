// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 *
 */

#include <config.h>
#include <imx.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>

struct csu_setting {
	int csu_index;
	uint32_t value;
};

const struct csu_setting csu_setting_imx6[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{16, 0x330033},		/* Protect TZASC */
	{26, 0xFF0033},		/* Protect OCRAM */
	{(-1), 0},
};

struct csu_sa_setting {
	uint32_t access_value;
	uint32_t lock_value;
};

struct csu_config {
	const struct csu_sa_setting * const sa;
	const struct csu_setting * const csl;
};

const struct csu_setting csu_setting_imx6ul[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{16, 0x3300FF},		/* Protect TZASC */
	{39, 0x3300FF},		/* Protect OCRAM */
	{(-1), 0},
};

const struct csu_setting csu_setting_imx6ull[] = {
	{ 13, 0xFF0033 },	/* Protect ROMCP */
	{ 16, 0x3300FF },	/* Protect TZASC */
	{ 34, 0xFF0033 },	/* Protect DCP */
	{ 39, 0x3300FF },	/* Protect OCRAM */
	{ (-1), 0 },
};

const struct csu_setting csu_setting_imx6sl[] = {
	{ 13, 0x3F0033 },	/* Protect DCP/ROMCP */
	{ 16, 0xFF0033 },	/* Protect TZASC */
	{ 26, 0xFF0033 },	/* Protect OCRAM */
	{ (-1), 0 },
};

const struct csu_setting csu_setting_imx6sx[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{15, 0xFF0033},		/* Protect RDC   */
	{16, 0x3300FF},		/* Protect TZASC */
	{34, 0x3300FF},		/* Protect OCRAM */
	{(-1), 0},
};

const struct csu_setting csu_setting_imx7ds[] = {
	{14, 0x3300FF},		/* Protect RDC     */
	{15, 0xFF0033},		/* Protect CSU     */
	{28, 0xFF0033},		/* Protect TZASC   */
	{59, 0x3300FF},		/* Protect OCRAM_S */
	{(-1), 0},
};

/* Set all masters to non-secure except the Cortex-A7 */
const struct csu_sa_setting csu_sa_imx6ul = { 0x10554550, 0x20aa8aa2 };

const struct csu_config csu_imx6 = { NULL, csu_setting_imx6 };
const struct csu_config csu_imx6ul = { &csu_sa_imx6ul, csu_setting_imx6ul };
const struct csu_config csu_imx6ull = { NULL, csu_setting_imx6ull };
const struct csu_config csu_imx6sl = { NULL, csu_setting_imx6sl };
const struct csu_config csu_imx6sx = { NULL, csu_setting_imx6sx };
const struct csu_config csu_imx7ds = { NULL, csu_setting_imx7ds };

static void rngb_configure(vaddr_t csu_base)
{
	int csu_index = 0;

	if (soc_is_imx6sl() || soc_is_imx6sll())
		csu_index = 16;
	else if (soc_is_imx6ull())
		csu_index = 34;
	else
		return;

	/* Protect RNGB */
	io_mask32(csu_base + csu_index * 4, 0x330000, 0xFF0000);
}

static TEE_Result csu_init(void)
{
	vaddr_t csu_base;
	vaddr_t offset;
	const struct csu_config *csu_config = NULL;
	const struct csu_setting *csu_setting = NULL;

	csu_base = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, 1);
	if (!csu_base)
		panic();

	if (soc_is_imx6sx())
		csu_config = &csu_imx6sx;
	else if (soc_is_imx6ul())
		csu_config = &csu_imx6ul;
	else if (soc_is_imx6ull())
		csu_config = &csu_imx6ull;
	else if (soc_is_imx6sll() || soc_is_imx6sl())
		csu_config = &csu_imx6sl;
	else if (soc_is_imx6())
		csu_config = &csu_imx6;
	else if (soc_is_imx7ds())
		csu_config = &csu_imx7ds;
	else
		return TEE_SUCCESS;

	/* first grant all peripherals */
	for (offset = CSU_CSL_START; offset < CSU_CSL_END; offset += 4)
		io_write32(csu_base + offset, CSU_ACCESS_ALL);

	csu_setting = csu_config->csl;

	while (csu_setting->csu_index >= 0) {
		io_write32(csu_base + (csu_setting->csu_index * 4),
				csu_setting->value);

		csu_setting++;
	}

	if (IS_ENABLED(CFG_IMX_RNGB))
		rngb_configure(csu_base);

	/* lock the settings */
	for (offset = CSU_CSL_START; offset < CSU_CSL_END; offset += 4) {
		io_write32(csu_base + offset,
			io_read32(csu_base + offset) | CSU_SETTING_LOCK);
	}

	if (csu_config->sa) {
		io_write32(csu_base + CSU_SA, csu_config->sa->access_value);
		io_setbits32(csu_base + CSU_SA, csu_config->sa->lock_value);
	}

	return TEE_SUCCESS;
}

driver_init(csu_init);
