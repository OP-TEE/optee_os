// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 * Copyright (c) 2024, Rockchip, Inc. All rights reserved.
 * Copyright (C) 2025, Pengutronix, Michael Tretter <m.tretter@pengutronix.de>
 */

#include <common.h>
#include <drivers/rockchip_otp.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <utee_defines.h>

#define OTP_S_AUTO_CTRL	0x0004
#define OTP_S_AUTO_EN	0x0008
#define OTP_S_PROG_DATA	0x0010
#define OTP_S_DOUT	0x0020
#define OTP_S_INT_ST	0x0084

#define ADDR_SHIFT	16
#define BURST_SHIFT	8
#define CMD_READ	0
#define CMD_WRITE	2
#define EN_ENABLE	1
#define EN_DISABLE	0

#define MAX_INDEX	0x300
#define BURST_SIZE	8
#define OTP_WORD	1

#define OTP_S_ERROR_BIT		BIT32(4)
#define OTP_S_WR_DONE_BIT	BIT32(3)
#define OTP_S_VERIFY_BIT	BIT32(2)
#define OTP_S_RD_DONE_BIT	BIT32(1)

#define OTP_POLL_PERIOD_US	0
#define OTP_POLL_TIMEOUT_US	1000

register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_S_BASE, OTP_S_SIZE);

TEE_Result rockchip_otp_read_secure(uint32_t *value, uint32_t index,
				    uint32_t count)
{
	vaddr_t base = (vaddr_t)phys_to_virt(OTP_S_BASE, MEM_AREA_IO_SEC,
					     OTP_S_SIZE);
	uint32_t int_status = 0;
	uint32_t i = 0;
	uint32_t val = 0;
	uint32_t auto_ctrl_val = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!base)
		panic("OTP_S base not mapped");

	/* Check for invalid parameters or exceeding hardware burst limit */
	if (!value || !count || count > BURST_SIZE ||
	    (index + count > MAX_INDEX))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Setup read: index, count, command = READ */
	auto_ctrl_val = SHIFT_U32(index, ADDR_SHIFT) |
			SHIFT_U32(count, BURST_SHIFT) |
			CMD_READ;

	/* Clear any pending interrupts by reading & writing back INT_ST */
	io_write32(base + OTP_S_INT_ST, io_read32(base + OTP_S_INT_ST));

	/* Set read command */
	io_write32(base + OTP_S_AUTO_CTRL, auto_ctrl_val);

	/* Enable read */
	io_write32(base + OTP_S_AUTO_EN, EN_ENABLE);

	/* Wait for RD_DONE or ERROR bits */
	res = IO_READ32_POLL_TIMEOUT(base + OTP_S_INT_ST,
				     int_status,
				     (int_status & OTP_S_RD_DONE_BIT) ||
				     (int_status & OTP_S_ERROR_BIT),
				     OTP_POLL_PERIOD_US,
				     OTP_POLL_TIMEOUT_US);

	/* Clear the interrupt again */
	io_write32(base + OTP_S_INT_ST, io_read32(base + OTP_S_INT_ST));

	if (int_status & OTP_S_ERROR_BIT) {
		EMSG("OTP_S Error");
		return TEE_ERROR_GENERIC;
	}
	if (res) {
		EMSG("OTP_S Timeout");
		return TEE_ERROR_BUSY;
	}

	/* Read out the data */
	for (i = 0; i < count; i++) {
		val = io_read32(base + OTP_S_DOUT +
				(i * sizeof(uint32_t)));
		value[i] = val;
	}

	return TEE_SUCCESS;
}

TEE_Result rockchip_otp_write_secure(const uint32_t *value, uint32_t index,
				     uint32_t count)
{
	vaddr_t base = (vaddr_t)phys_to_virt(OTP_S_BASE, MEM_AREA_IO_SEC,
					     OTP_S_SIZE);
	uint32_t int_status = 0;
	uint32_t i = 0;

	if (!base)
		panic("OTP_S base not mapped");

	/* Check for invalid parameters or exceeding hardware limits */
	if (!value || !count || count > BURST_SIZE ||
	    (index + count > MAX_INDEX))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Program OTP words */
	for (i = 0; i < count; i++) {
		uint32_t old_val = 0;
		uint32_t new_val = 0;
		uint32_t curr_idx = index + i;
		TEE_Result res = TEE_SUCCESS;

		/* Setup write: curr_idx, command = WRITE */
		uint32_t auto_ctrl_val = SHIFT_U32(curr_idx, ADDR_SHIFT) |
						   CMD_WRITE;

		/* Read existing OTP word to see which bits can be set */
		res = rockchip_otp_read_secure(&old_val, curr_idx, OTP_WORD);
		if (res != TEE_SUCCESS)
			return res;

		/* Check if bits in value conflict with old_val */
		if (~*value & old_val) {
			EMSG("OTP_S Program fail");
			return TEE_ERROR_GENERIC;
		}

		/* Only program bits that are currently 0 (0->1) */
		new_val = *value & ~old_val;
		value++;
		if (!new_val)
			continue;

		/* Clear any pending interrupts */
		io_write32(base + OTP_S_INT_ST, io_read32(base + OTP_S_INT_ST));

		/* Set write command */
		io_write32(base + OTP_S_AUTO_CTRL, auto_ctrl_val);

		/* Write the new bits into PROG_DATA register */
		io_write32(base + OTP_S_PROG_DATA, new_val);

		/* Enable the write */
		io_write32(base + OTP_S_AUTO_EN, EN_ENABLE);

		/* Poll for WR_DONE or verify/error bits */
		res = IO_READ32_POLL_TIMEOUT(base + OTP_S_INT_ST,
					     int_status,
					     (int_status & OTP_S_WR_DONE_BIT) ||
					     (int_status & OTP_S_VERIFY_BIT) ||
					     (int_status & OTP_S_ERROR_BIT),
					     OTP_POLL_PERIOD_US,
					     OTP_POLL_TIMEOUT_US);

		/* Clear INT status bits */
		io_write32(base + OTP_S_INT_ST, int_status);

		/* Check for VERIFY_FAIL, ERROR or timeout */
		if (int_status & OTP_S_VERIFY_BIT) {
			EMSG("OTP_S Verification fail");
			return TEE_ERROR_GENERIC;
		}
		if (int_status & OTP_S_ERROR_BIT) {
			EMSG("OTP_S Error");
			return TEE_ERROR_GENERIC;
		}
		if (res) {
			EMSG("OTP_S Timeout");
			return TEE_ERROR_BUSY;
		}
	}

	return TEE_SUCCESS;
}
