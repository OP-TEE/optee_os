// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Foundries.io Ltd.
 *
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <drivers/zynqmp_csu.h>
#include <drivers/zynqmp_csu_aes.h>
#include <drivers/zynqmp_csu_puf.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>

#define PUF_CMD_OFFSET			0x00
#define PUF_CFG0_OFFSET			0x04
#define PUF_CFG1_OFFSET			0x08
#define PUF_SHUT_OFFSET			0x0C
#define PUF_STATUS_OFFSET		0x10
#define PUF_WORD_OFFSET			0x18

#define PUF_REGENERATION		4
#define PUF_RESET			6

#define PUF_CFG0_DEFAULT		0x02
#define PUF_SHUT_DEFAULT		0x01000100
#define PUF_REGEN_TIME_MS		6

TEE_Result zynqmp_csu_puf_regenerate(void)
{
	vaddr_t puf = core_mmu_get_va(ZYNQMP_CSU_PUF_BASE, MEM_AREA_IO_SEC,
				      ZYNQMP_CSU_PUF_SIZE);
	vaddr_t csu = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, CSU_SIZE);
	uint32_t status = 0;

	if (!puf || !csu)
		return TEE_ERROR_GENERIC;

	io_write32(puf + PUF_CFG0_OFFSET, PUF_CFG0_DEFAULT);
	io_write32(puf + PUF_SHUT_OFFSET, PUF_SHUT_DEFAULT);
	io_write32(puf + PUF_CMD_OFFSET, PUF_REGENERATION);
	mdelay(PUF_REGEN_TIME_MS);

	status = io_read32(csu + ZYNQMP_CSU_ISR_OFFSET);
	if (status & ZYNQMP_CSU_ISR_PUF_ACC_ERROR_MASK) {
		EMSG("regeneration failed");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

void zynqmp_csu_puf_reset(void)
{
	vaddr_t puf = core_mmu_get_va(ZYNQMP_CSU_PUF_BASE, MEM_AREA_IO_SEC,
				      ZYNQMP_CSU_PUF_SIZE);

	io_write32(puf + PUF_CMD_OFFSET, PUF_RESET);
}

static TEE_Result zynqmp_csu_puf_init(void)
{
	vaddr_t csu = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, CSU_SIZE);
	uint32_t status = 0;

	/* if the bootloader has been authenticated, reserve the PUF */
	status = io_read32(csu + ZYNQMP_CSU_STATUS_OFFSET);
	if (status & ZYNQMP_CSU_STATUS_AUTH)
		return zynqmp_csu_aes_dt_enable_secure_status();

	return TEE_SUCCESS;
}

driver_init(zynqmp_csu_puf_init);
