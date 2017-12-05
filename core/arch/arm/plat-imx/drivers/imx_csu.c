// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 *
 */

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

const struct csu_setting csu_setting_imx6ul[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{16, 0x3300FF},		/* Protect TZASC */
	{39, 0x3300FF},		/* Protect OCRAM */
	{(-1), 0},
};

const struct csu_setting csu_setting_imx6sl[] = {
	{13, 0xFF0033},		/* Protect ROMCP */
	{16, 0xFF0033},		/* Protect TZASC */
	{26, 0xFF0033},		/* Protect OCRAM */
	{(-1), 0},
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

static TEE_Result csu_init(void)
{
	vaddr_t csu_base;
	vaddr_t offset;
	const struct csu_setting *csu_setting = NULL;

	csu_base = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC);
	if (!csu_base)
		panic();

	if (soc_is_imx6sx())
		csu_setting = csu_setting_imx6sx;
	else if (soc_is_imx6ul() || soc_is_imx6ull())
		csu_setting = csu_setting_imx6ul;
	else if (soc_is_imx6sl())
		csu_setting = csu_setting_imx6sl;
	else if (soc_is_imx6())
		csu_setting = csu_setting_imx6;
	else if (soc_is_imx7ds())
		csu_setting = csu_setting_imx7ds;
	else
		return TEE_SUCCESS;

	/* first grant all peripherals */
	for (offset = CSU_CSL_START; offset < CSU_CSL_END; offset += 4)
		io_write32(csu_base + offset, CSU_ACCESS_ALL);

	while (csu_setting->csu_index > 0) {
		io_write32(csu_base + (csu_setting->csu_index * 4),
				csu_setting->value);

		csu_setting++;
	}

	/* lock the settings */
	for (offset = CSU_CSL_START; offset < CSU_CSL_END; offset += 4) {
		io_write32(csu_base + offset,
			io_read32(csu_base + offset) | CSU_SETTING_LOCK);
	}

	return TEE_SUCCESS;
}

driver_init(csu_init);
