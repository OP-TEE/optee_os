// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <drivers/tcc_otp.h>
#include <io.h>
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
#define STATUS_READY		U(0x1)

/* READ_STATUS */
#define DATA_ERR		(U(0x1) << 3)
#define PERMISSION_ERR          (U(0x1) << 0)

/* OTP_CONTROL Register */
#define CTRL_DONE		(U(0x1) << 16)
#define CTRL_START		(U(0x1) << 0)
#define CTRL_CMD_PROG		(U(0xA) << 4)
#define CTRL_CMD_READ		(U(0xF) << 4)

register_phys_mem(MEM_AREA_IO_SEC, OTP_CMD_BASE, OTP_CMD_SIZE);

TEE_Result tcc_otp_read_128(uint32_t offset, uint32_t *buf)
{
	vaddr_t reg = (vaddr_t)phys_to_virt_io(OTP_CMD_BASE, OTP_CMD_SIZE);
	TEE_Result res = TEE_ERROR_BAD_STATE;
	uint32_t status = 0;

	if (((offset % U(16)) != U(0)) || offset >= OTPROM_128_LIMIT ||
	    offset < OTPROM_128_START || !buf || reg == 0) {
		EMSG("Invalid parameters");
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		do {
		} while ((io_read32(reg + GENERAL_STATUS) & STATUS_READY) == 0);
		io_write32(reg + OTP_ADDRESS, offset);
		io_write32(reg + OTP_CONTROL, CTRL_CMD_READ | CTRL_START);
		do {
		} while ((io_read32(reg + OTP_CONTROL) & CTRL_DONE) == 0);
		if ((io_read32(reg + READ_ADMIN_INFO0) & U(1)) == U(1)) {
			status = io_read32(reg + READ_STATUS);
			if ((status & (DATA_ERR | PERMISSION_ERR)) == U(0)) {
				buf[0] = io_read32(reg + READ_DATA_PAYLOAD0);
				buf[1] = io_read32(reg + READ_DATA_PAYLOAD1);
				buf[2] = io_read32(reg + READ_DATA_PAYLOAD2);
				buf[3] = io_read32(reg + READ_DATA_PAYLOAD3);
				res = TEE_SUCCESS;
			} else {
				EMSG("Failed to read OTP (0x%08x)", status);
			}
		} else {
			if (io_read32(reg + READ_ADMIN_INFO0) == U(0)) {
				if (io_read32(reg + READ_STATUS) == U(0))
					res = TEE_ERROR_NO_DATA;
			}
		}
	}

	return res;
}

TEE_Result tcc_otp_write_128(uint32_t offset, const uint32_t *buf)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	vaddr_t reg = (vaddr_t)phys_to_virt_io(OTP_CMD_BASE, OTP_CMD_SIZE);
	vaddr_t ctrl = (vaddr_t)phys_to_virt_io(OTP_CTRL_BASE, OTP_CTRL_SIZE);

	if (((offset % U(16)) != U(0)) || offset >= OTPROM_128_LIMIT ||
	    offset < OTPROM_128_START || !buf || reg == 0) {
		EMSG("Invalid parameters");
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((io_read32(ctrl) & (U(1) << 30)) != 0) {
		EMSG("EXT_WP is high");
	} else {
		do {
		} while ((io_read32(reg + GENERAL_STATUS) & STATUS_READY) == 0);
		io_clrbits32(ctrl, U(1) << 3);
		io_write32(reg + OTP_ADDRESS, offset);
		io_write32(reg + PROG_DATA_PAYLOAD0, buf[0]);
		io_write32(reg + PROG_DATA_PAYLOAD1, buf[1]);
		io_write32(reg + PROG_DATA_PAYLOAD2, buf[2]);
		io_write32(reg + PROG_DATA_PAYLOAD3, buf[3]);
		io_write32(reg + PROG_ADMIN_INFO0, U(0));
		io_write32(reg + PROG_ADMIN_INFO1, U(0));
		io_write32(reg + PROG_ADMIN_INFO2, U(0));
		io_write32(reg + PROG_ADMIN_INFO3, U(0));
		io_write32(reg + OTP_CONTROL, CTRL_CMD_PROG | CTRL_START);
		do {
		} while ((io_read32(reg + OTP_CONTROL) & CTRL_DONE) == 0);
		io_setbits32(ctrl, U(1) << 3);
		res = TEE_SUCCESS;
	}

	return res;
}
