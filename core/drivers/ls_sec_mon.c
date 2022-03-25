// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microsoft
 *
 * Driver for the NXP LX2160A-series Security Monitor (SecMon).
 */

#include <drivers/ls_sec_mon.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <util.h>

/**
 * struct ls_sec_mon_registers - Memory map of the SecMon registers.
 * hplr;		HP Lock Register.
 * @hpcomr:		HP Command Register.
 * @rsvd0:		Reserved.
 * @hpsicr:		HP Security Interrupt Control Register.
 * @hpsvcr:		HP Security Violation Control Register.
 * @hpsr:		HP Status Register.
 * @hpsvsr:		HP Security Violation Status Register.
 * @hphacivr:		HP High Assurance Counter IV Register.
 * @hphacr:		HP High Assurance Counter Register.
 * @rsvd1[0x4]:		Reserved.
 * @lplr:		LP Lock Register.
 * @lpcr:		LP Control Register.
 * @lpmkcr:		LP Master Key Control Register.
 * @lpsvcr:		LP Security Violation Control Register.
 * @rsvd2:		Reserved.
 * @lptdcr:		LP Tamper Detectors Configuration.
 * @lpsr:		LP Status Register.
 * @rsvd3[0x3]:		Reserved.
 * @lpsmcmr:		LP Secure Monotonic Counter MSB Register.
 * @lpsmclr:		LP Secure Monotonic Counter LSB Register.
 * @lppgdr:		LP Power Glitch Detector Register.
 * @rsvd4:		Reserved.
 * @lpzmkr[0x8]:	LP Zeroizable Master Key Registers.
 * @lpgpr[0x4]:		LP General Purpose Registers.
 * @rsvd5[0x2d2]:	Reserved.
 * @hpvidr1:		HP Version ID Register 1.
 * @hpvidr2:		HP Version ID Register 2.
 */
static struct ls_sec_mon_registers {
	uint32_t hplr;			/* 0x000 */
	uint32_t hpcomr;		/* 0x004 */
	uint32_t rsvd0;			/* 0x008 */
	uint32_t hpsicr;		/* 0x00C */
	uint32_t hpsvcr;		/* 0x010 */
	uint32_t hpsr;			/* 0x014 */
	uint32_t hpsvsr;		/* 0x018 */
	uint32_t hphacivr;		/* 0x01C */
	uint32_t hphacr;		/* 0x020 */
	uint32_t rsvd1[0x4];		/* 0x024 */
	uint32_t lplr;			/* 0x034 */
	uint32_t lpcr;			/* 0x038 */
	uint32_t lpmkcr;		/* 0x03C */
	uint32_t lpsvcr;		/* 0x040 */
	uint32_t rsvd2;			/* 0x044 */
	uint32_t lptdcr;		/* 0x048 */
	uint32_t lpsr;			/* 0x04C */
	uint32_t rsvd3[0x3];		/* 0x050 */
	uint32_t lpsmcmr;		/* 0x05C */
	uint32_t lpsmclr;		/* 0x060 */
	uint32_t lppgdr;		/* 0x064 */
	uint32_t rsvd4;			/* 0x068 */
	uint32_t lpzmkr[0x8];		/* 0x06C */
	uint32_t lpgpr[0x4];		/* 0x090 */
	uint32_t rsvd5[0x2d2];		/* 0x0B0 */
	uint32_t hpvidr1;		/* 0xBF8 */
	uint32_t hpvidr2;		/* 0xBFC */
} *sec_mon_regs;

/**
 * ls_sec_mon_init() - Initialize the SecMon driver and assign the sec_mon_regs
 *		       pointer to the SecMon base address detailed in the device
 *		       tree.
 *
 * Return:	0 if successful or > 0 on error.
 */
static TEE_Result ls_sec_mon_init(void)
{
	void *fdt = NULL;
	size_t size = 0;
	uint32_t node = 0;
	vaddr_t ctrl_base = 0;

	fdt = get_embedded_dt();
	if (!fdt) {
		EMSG("Unable to find the device tree");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	node = fdt_node_offset_by_compatible(fdt, node, "fsl,lx2160a-sec-mon");
	if (node <= 0) {
		EMSG("Unable to find the SecMon device tree node");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (dt_map_dev(fdt, node, &ctrl_base, &size, DT_MAP_AUTO) < 0) {
		EMSG("Unable to get the SecMon virtual address");
		return TEE_ERROR_GENERIC;
	}

	sec_mon_regs = (struct ls_sec_mon_registers *)ctrl_base;

	return TEE_SUCCESS;
}

TEE_Result ls_sec_mon_read(struct ls_sec_mon_data *data)
{
	if (!sec_mon_regs) {
		EMSG("SecMon driver is not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!data) {
		EMSG("Given buffer is uninitialized");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	data->hplr = io_read32((vaddr_t)&sec_mon_regs->hplr);
	data->hpcomr = io_read32((vaddr_t)&sec_mon_regs->hpcomr);
	data->hpsicr = io_read32((vaddr_t)&sec_mon_regs->hpsicr);
	data->hpsvcr = io_read32((vaddr_t)&sec_mon_regs->hpsvcr);
	data->hpsr = io_read32((vaddr_t)&sec_mon_regs->hpsr);
	data->hpsvsr = io_read32((vaddr_t)&sec_mon_regs->hpsvsr);
	data->hphacivr = io_read32((vaddr_t)&sec_mon_regs->hphacivr);
	data->hphacr = io_read32((vaddr_t)&sec_mon_regs->hphacr);
	data->lplr = io_read32((vaddr_t)&sec_mon_regs->lplr);
	data->lpcr = io_read32((vaddr_t)&sec_mon_regs->lpcr);
	data->lpmkcr = io_read32((vaddr_t)&sec_mon_regs->lpmkcr);
	data->lpsvcr = io_read32((vaddr_t)&sec_mon_regs->lpsvcr);
	data->lptdcr = io_read32((vaddr_t)&sec_mon_regs->lptdcr);
	data->lpsr = io_read32((vaddr_t)&sec_mon_regs->lpsr);
	data->lpsmcmr = io_read32((vaddr_t)&sec_mon_regs->lpsmcmr);
	data->lpsmclr = io_read32((vaddr_t)&sec_mon_regs->lpsmclr);
	data->lppgdr = io_read32((vaddr_t)&sec_mon_regs->lppgdr);
	data->hpvidr1 = io_read32((vaddr_t)&sec_mon_regs->hpvidr1);
	data->hpvidr2 = io_read32((vaddr_t)&sec_mon_regs->hpvidr2);

	for (uint32_t i = 0; i < ARRAY_SIZE(data->lpzmkr); ++i)
		data->lpzmkr[i] = io_read32((vaddr_t)&sec_mon_regs->lpzmkr[i]);

	for (uint32_t i = 0; i < ARRAY_SIZE(data->lpgpr); ++i)
		data->lpgpr[i] = io_read32((vaddr_t)&sec_mon_regs->lpgpr[i]);

	return TEE_SUCCESS;
}

TEE_Result ls_sec_mon_status(void)
{
	if (!sec_mon_regs)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

driver_init(ls_sec_mon_init);
