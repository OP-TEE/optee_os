// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <drivers/tcc_otp.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <otprom.h>
#include <string.h>

#define OTP_CTRL_SIZE		U(0x1000)
#define OTP_CMD_SIZE		U(0x1000)

#define GENERAL_STATUS		U(0x0)
#define READ_STATUS		U(0x4)
#define PROG_STATUS		U(0x8)
#define OTP_ADDRESS		U(0x10)
#define OTP_CONTROL		U(0x14)
#define READ_DATA_PAYLOAD0	U(0x20)
#define READ_DATA_PAYLOAD1	U(0x24)
#define READ_DATA_PAYLOAD2	U(0x28)
#define READ_DATA_PAYLOAD3	U(0x2C)
#define READ_ADMIN_INFO0	U(0x30)
#define READ_ADMIN_INFO1	U(0x34)
#define READ_ADMIN_INFO2	U(0x38)
#define READ_ADMIN_INFO3	U(0x3C)
#define PROG_DATA_PAYLOAD0	U(0x40)
#define PROG_DATA_PAYLOAD1	U(0x44)
#define PROG_DATA_PAYLOAD2	U(0x48)
#define PROG_DATA_PAYLOAD3	U(0x4C)
#define PROG_ADMIN_INFO0	U(0x50)
#define PROG_ADMIN_INFO1	U(0x54)
#define PROG_ADMIN_INFO2	U(0x58)
#define PROG_ADMIN_INFO3	U(0x5C)

/* GENERAL_STATUS */
#define STATUS_READY		BIT(0)

/* READ_STATUS */
#define DATA_ERR		BIT(3)
#define PERMISSION_ERR          BIT(0)

/* OTP_CONTROL Register */
#define CTRL_DONE		BIT(16)
#define CTRL_START		BIT(0)
#define CTRL_CMD_PROG		SHIFT_U32(0xA, 4)
#define CTRL_CMD_READ		SHIFT_U32(0xF, 4)

/* Admin Info */
#define ADMIN_VALID		BIT(0)

/* Write Protection Control */
#define EXT_WP			BIT(30)
#define SOFT_WP			BIT(3)

#define IS_16BYTE_ALIGNED(x)	IS_ALIGNED(x, 16)

register_phys_mem(MEM_AREA_IO_SEC, OTP_CMD_BASE, OTP_CMD_SIZE);

static void wait_for_ready(vaddr_t reg)
{
	while (!(io_read32(reg + GENERAL_STATUS) & STATUS_READY))
		udelay(1);
}

static void wait_for_done(vaddr_t reg)
{
	while (!(io_read32(reg + OTP_CONTROL) & CTRL_DONE))
		udelay(1);
}

TEE_Result tcc_otp_read_128(uint32_t offset, uint32_t *buf)
{
	vaddr_t reg = (vaddr_t)phys_to_virt_io(OTP_CMD_BASE, OTP_CMD_SIZE);
	uint32_t status = 0;
	uint32_t admin_info0 = 0;

	if (!IS_16BYTE_ALIGNED(offset) || offset >= OTPROM_128_LIMIT ||
	    offset < OTPROM_128_START || !buf || !reg) {
		EMSG("Invalid parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wait_for_ready(reg);
	io_write32(reg + OTP_ADDRESS, offset);
	io_write32(reg + OTP_CONTROL, CTRL_CMD_READ | CTRL_START);
	wait_for_done(reg);

	admin_info0 = io_read32(reg + READ_ADMIN_INFO0);
	if (!(admin_info0 & ADMIN_VALID)) {
		if (!admin_info0 && !io_read32(reg + READ_STATUS))
			return TEE_ERROR_NO_DATA;
		return TEE_ERROR_BAD_STATE;
	}

	status = io_read32(reg + READ_STATUS);
	if (status & (DATA_ERR | PERMISSION_ERR)) {
		EMSG("Failed to read OTP (%#"PRIx32")", status);
		return TEE_ERROR_BAD_STATE;
	}

	buf[0] = io_read32(reg + READ_DATA_PAYLOAD0);
	buf[1] = io_read32(reg + READ_DATA_PAYLOAD1);
	buf[2] = io_read32(reg + READ_DATA_PAYLOAD2);
	buf[3] = io_read32(reg + READ_DATA_PAYLOAD3);

	return TEE_SUCCESS;
}

TEE_Result tcc_otp_write_128(uint32_t offset, const uint32_t *buf)
{
	vaddr_t reg = (vaddr_t)phys_to_virt_io(OTP_CMD_BASE, OTP_CMD_SIZE);
	vaddr_t ctrl = (vaddr_t)phys_to_virt_io(OTP_CTRL_BASE, OTP_CTRL_SIZE);

	if (!IS_16BYTE_ALIGNED(offset) || offset >= OTPROM_128_LIMIT ||
	    offset < OTPROM_128_START || !buf || !reg) {
		EMSG("Invalid parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (io_read32(ctrl) & EXT_WP) {
		EMSG("EXT_WP is high");
		return TEE_ERROR_BAD_STATE;
	}

	wait_for_ready(reg);
	io_clrbits32(ctrl, SOFT_WP);
	io_write32(reg + OTP_ADDRESS, offset);
	io_write32(reg + PROG_DATA_PAYLOAD0, buf[0]);
	io_write32(reg + PROG_DATA_PAYLOAD1, buf[1]);
	io_write32(reg + PROG_DATA_PAYLOAD2, buf[2]);
	io_write32(reg + PROG_DATA_PAYLOAD3, buf[3]);
	io_write32(reg + PROG_ADMIN_INFO0, 0);
	io_write32(reg + PROG_ADMIN_INFO1, 0);
	io_write32(reg + PROG_ADMIN_INFO2, 0);
	io_write32(reg + PROG_ADMIN_INFO3, 0);
	io_write32(reg + OTP_CONTROL, CTRL_CMD_PROG | CTRL_START);
	wait_for_done(reg);
	io_setbits32(ctrl, SOFT_WP);

	return  TEE_SUCCESS;
}
