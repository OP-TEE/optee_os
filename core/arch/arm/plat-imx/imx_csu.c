// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <mm/core_memprot.h>
#include <io.h>

#include <imx.h>
#include <imx-regs.h>

struct csu_setting {
	int      csu_index;
	uint32_t value;
};

const struct csu_setting csu_setting_imx6[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{14, 0x3F00FF},		/* Protect OCOTP */
	{16, 0x330033},		/* Protect TZASC */
	{26, 0xFF0033},		/* Protect OCRAM */
	{(-1), 0},
};

const struct csu_setting csu_setting_imx6ul[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{14, 0x3F00FF},		/* Protect OCOTP */
	{16, 0x3300FF},		/* Protect TZASC */
	{(-1), 0},
};

const struct csu_setting csu_setting_imx6sx[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{14, 0x3F00FF},		/* Protect OCOTP */
	{15, 0xFF0033},		/* Protect RDC   */
	{16, 0x3300FF},		/* Protect TZASC */
	{(-1), 0},
};

const struct csu_setting csu_setting_imx7ds[] = {
	{14, 0x3300FF},		/* Protect RDC     */
	{15, 0xFF0033},		/* Protect CSU     */
	{28, 0xFF0033},		/* Protect TZASC   */
	{59, 0xFF0033},		/* Protect OCRAM_S */
	{(-1), 0},
};

TEE_Result csu_init(void)
{
	vaddr_t csu_base = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC);
	vaddr_t offset;
	const struct csu_setting *csu_setting = NULL;

	if (soc_is_imx6sx()) {
		csu_setting = csu_setting_imx6sx;
	} else if (soc_is_imx6ul() || soc_is_imx6ull()) {
		csu_setting = csu_setting_imx6ul;
	} else if (soc_is_imx6()) {
		csu_setting = csu_setting_imx6;
	} else if (soc_is_imx7ds()) {
		csu_setting = csu_setting_imx7ds;
	} else {
		return TEE_SUCCESS;
	}

	/* configure imx6 CSU */
	/* first grant all peripherals */
	for (offset = CSU_CSL_START; offset < CSU_CSL_END; offset += 4) {
		write32(CSU_ACCESS_ALL, csu_base + offset);
	}

	while (csu_setting->csu_index > 0) {
		write32(csu_setting->value,
				csu_base + (csu_setting->csu_index * 4));

		csu_setting++;
	}

	/* lock the settings */
	for (offset = CSU_CSL_START; offset < CSU_CSL_END; offset += 4) {
		write32(read32(csu_base + offset) | CSU_SETTING_LOCK,
				csu_base + offset);
	}

	return TEE_SUCCESS;
}

