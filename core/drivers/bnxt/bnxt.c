// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm/bnxt.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BNXT_REG_CTRL_BASE			0x3040000
#define BNXT_REG_ECO_RESERVED			0x3042400
#define BNXT_FLASH_ACCESS_DONE_BIT		2
#define NIC400_BNXT_IDM_IO_CONTROL_DIRECT	0x60e00408
#define BNXT_INDIRECT_BASE			0x60800000
#define BNXT_INDIRECT_ADDR_MASK			0x3fffffu
#define BNXT_INDIRECT_BASE_MASK			(~BNXT_INDIRECT_ADDR_MASK)
#define BNXT_INDIRECT_WINDOW_SIZE		(BNXT_INDIRECT_ADDR_MASK + 1)
#define BNXT_REG_CTRL_BPE_MODE_REG		0x0
#define BNXT_REG_CTRL_BPE_MODE_FASTBOOT_MODE_BIT	2
#define BNXT_REG_CTRL_BPE_MODE_CM3_RST_BIT	1
#define BNXT_REG_CTRL_BPE_STAT_REG		0x4
#define BNXT_REG_CTRL_FSTBOOT_PTR_REG		0x8
#define BNXT_ERROR_MASK				0xf0000000
#define BNXT_CTRL_ADDR(x)			(BNXT_REG_CTRL_BASE + (x))
#define BNXT_HANDSHAKE_TIMEOUT_MS		1000

#define KONG_REG_CTRL_MODE_REG			0x03900000
#define KONG_REG_CTRL_MODE_CPUHALT_N_BIT	0

#define BNXT_STICKY_BYTE_POR			0x04030088
#define BNXT_STICKY_BYTE_POR_MHB_BIT		4

#define BNXT_HEALTH_CHECK_REG			0x03100008

enum bnxt_handshake_sts {
	BNXT_HANDSHAKE_SUCCESS = 0,
	BNXT_HANDSHAKE_WAIT_ERROR,
	BNXT_HANDSHAKE_WAIT_TIMEOUT
};

static vaddr_t bnxt_access_window_virt_addr;
static vaddr_t bnxt_indirect_dest_addr;

static void bnxt_prepare_access_window(uint32_t addr)
{
	addr &= BNXT_INDIRECT_BASE_MASK;
	io_write32(bnxt_access_window_virt_addr, addr);
}

static vaddr_t bnxt_indirect_tgt_addr(uint32_t addr)
{
	addr &= BNXT_INDIRECT_ADDR_MASK;
	return (vaddr_t)(bnxt_indirect_dest_addr + addr);
}

uint32_t bnxt_write32_multiple(uintptr_t dst,
			       uintptr_t src,
			       uint32_t num_entries,
			       int src_4byte_increment)
{
	uint32_t i = 0;
	vaddr_t target = 0;

	if (num_entries == 0)
		return 0;

	/* Only write up to the next window boundary */
	if ((dst & BNXT_INDIRECT_BASE_MASK) !=
	    ((dst + num_entries * sizeof(uint32_t)) & BNXT_INDIRECT_BASE_MASK))
		num_entries = (((dst + BNXT_INDIRECT_WINDOW_SIZE) &
				BNXT_INDIRECT_BASE_MASK) -
			       dst) /
			      sizeof(uint32_t);

	bnxt_prepare_access_window(dst);
	target = bnxt_indirect_tgt_addr(dst);
	for (i = 0; i < num_entries; i++) {
		io_write32(target, *(uint32_t *)src);
		target += sizeof(uint32_t);
		if (src_4byte_increment)
			src += sizeof(uint32_t);
	}

	return num_entries;
}

static uint32_t bnxt_read(uint32_t addr)
{
	bnxt_prepare_access_window(addr);
	return io_read32(bnxt_indirect_tgt_addr(addr));
}

static uint32_t bnxt_read_ctrl(uint32_t offset)
{
	return bnxt_read(BNXT_CTRL_ADDR(offset));
}

static void bnxt_write(uint32_t addr, uint32_t value)
{
	bnxt_prepare_access_window(addr);
	io_write32(bnxt_indirect_tgt_addr(addr), value);
}

static void bnxt_write_ctrl(uint32_t offset, uint32_t value)
{
	bnxt_write(BNXT_CTRL_ADDR(offset), value);
}

void bnxt_handshake_clear(void)
{
	uint32_t value = bnxt_read(BNXT_REG_ECO_RESERVED);

	value = value & ~BIT(BNXT_FLASH_ACCESS_DONE_BIT);
	bnxt_write(BNXT_REG_ECO_RESERVED, value);
}

static int bnxt_handshake_done(void)
{
	uint32_t value = 0;

	value = bnxt_read(BNXT_REG_ECO_RESERVED);
	value &= BIT(BNXT_FLASH_ACCESS_DONE_BIT);

	return value != 0;
}

uint32_t bnxt_wait_handshake(uint32_t max_timeout)
{
	int ret = 0;
	uint32_t status = 0;
	uint32_t timeout = 0;

	/* If no timeout given we go with max timeout */
	if (max_timeout == 0)
		max_timeout = BNXT_HANDSHAKE_TIMEOUT_MS;

	timeout = max_timeout;

	DMSG("Waiting for ChiMP handshake...");
	do {
		if (bnxt_handshake_done()) {
			ret = BNXT_HANDSHAKE_SUCCESS;
			break;
		}
		/* No need to wait if ChiMP reported an error */
		status = bnxt_read_ctrl(BNXT_REG_CTRL_BPE_STAT_REG);
		if (status & BNXT_ERROR_MASK) {
			EMSG("ChiMP error 0x%x. Wait aborted", status);
			ret = BNXT_HANDSHAKE_WAIT_ERROR;
			break;
		}
		mdelay(1);
	} while (--timeout);

	if (!bnxt_handshake_done()) {
		if (timeout == 0) {
			ret = BNXT_HANDSHAKE_WAIT_TIMEOUT;
			EMSG("Timeout waiting for ChiMP handshake");
		}
	} else {
		ret = BNXT_HANDSHAKE_SUCCESS;
		DMSG("ChiMP handshake successful");
	}

	return ret;
}

void bnxt_chimp_halt(void)
{
	uint32_t value = 0;

	value = bnxt_read_ctrl(BNXT_REG_CTRL_BPE_MODE_REG);
	value |= BIT(BNXT_REG_CTRL_BPE_MODE_CM3_RST_BIT);
	bnxt_write_ctrl(BNXT_REG_CTRL_BPE_MODE_REG, value);
}

void bnxt_kong_halt(void)
{
	uint32_t value = 0;

	value = bnxt_read(KONG_REG_CTRL_MODE_REG);
	value &= ~BIT(KONG_REG_CTRL_MODE_CPUHALT_N_BIT);
	bnxt_write(KONG_REG_CTRL_MODE_REG, value);
}

int bnxt_fastboot(uintptr_t addr)
{
	uint32_t value = 0;

	value = bnxt_read(BNXT_STICKY_BYTE_POR);
	value |= BIT(BNXT_STICKY_BYTE_POR_MHB_BIT);
	bnxt_write(BNXT_STICKY_BYTE_POR, value);

	/* Set the fastboot address and type */
	bnxt_write_ctrl(BNXT_REG_CTRL_FSTBOOT_PTR_REG, addr);

	/* Set fastboot mode & take BNXT CPU1 out of reset */
	value = bnxt_read_ctrl(BNXT_REG_CTRL_BPE_MODE_REG);
	value |= BIT(BNXT_REG_CTRL_BPE_MODE_FASTBOOT_MODE_BIT);
	value &= ~BIT(BNXT_REG_CTRL_BPE_MODE_CM3_RST_BIT);
	bnxt_write_ctrl(BNXT_REG_CTRL_BPE_MODE_REG, value);

	return 0;
}

uint32_t bnxt_health_status(void)
{
	return bnxt_read(BNXT_HEALTH_CHECK_REG);
}

static TEE_Result bnxt_init(void)
{
	bnxt_access_window_virt_addr =
		(vaddr_t)phys_to_virt(NIC400_BNXT_IDM_IO_CONTROL_DIRECT,
				      MEM_AREA_IO_SEC, sizeof(uint32_t));
	bnxt_indirect_dest_addr =
		(vaddr_t)phys_to_virt(BNXT_INDIRECT_BASE,
				      MEM_AREA_IO_SEC,
				      BNXT_INDIRECT_WINDOW_SIZE);
	return TEE_SUCCESS;
}
driver_init(bnxt_init);
