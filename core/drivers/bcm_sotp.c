// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <assert.h>
#include <drivers/bcm_sotp.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <util.h>

#define SOTP_PROG_CONTROL			0x0
#define SOTP_PROG_CONTROL__OTP_CPU_MODE_EN	BIT(15)
#define SOTP_PROG_CONTROL__OTP_DISABLE_ECC	BIT(9)
#define SOTP_ADDR__OTP_ROW_ADDR_R		6

#define SOTP_ADDR				0xc

#define SOTP_CTRL_0				0x10
#define SOTP_CTRL_0__START			1
#define SOTP_READ				0

#define SOTP_STAT_0				0x18
#define SOTP_STATUS_0__FDONE			BIT(3)

#define SOTP_STATUS_1				0x1c
#define SOTP_STATUS_1__CMD_DONE			BIT(1)
#define SOTP_STATUS_1__ECC_DET			BIT(17)

#define SOTP_RDDATA_0				0x20
#define SOTP_RDDATA_1				0x24
#define SOTP_ADDR_MASK				0x3ff

#define SOTP_ECC_ERR_DETECT			BIT64(63)

#define SOTP_TIMEOUT_US				300

static vaddr_t bcm_sotp_base;

static TEE_Result otp_status_done_wait(vaddr_t addr, uint32_t bit)
{
	uint64_t timeout = timeout_init_us(SOTP_TIMEOUT_US);

	while (!(io_read32(addr) & bit))
		if (timeout_elapsed(timeout))
			return TEE_ERROR_BUSY;
	return TEE_SUCCESS;
}

TEE_Result bcm_iproc_sotp_mem_read(uint32_t row_addr, uint32_t sotp_add_ecc,
				uint64_t *rdata)
{
	uint64_t read_data = 0;
	uint32_t reg_val = 0;
	TEE_Result ret = TEE_SUCCESS;

	assert(bcm_sotp_base);
	/* Check for FDONE status */
	ret = otp_status_done_wait((bcm_sotp_base + SOTP_STAT_0),
				   SOTP_STATUS_0__FDONE);
	if (ret) {
		EMSG("FDONE status done wait failed");
		return ret;
	}

	/* Enable OTP access by CPU */
	io_setbits32((bcm_sotp_base + SOTP_PROG_CONTROL),
		     SOTP_PROG_CONTROL__OTP_CPU_MODE_EN);

	/* ROWS does not support ECC */
	if (row_addr <= SOTP_NO_ECC_ROWS)
		sotp_add_ecc = 0;

	if (sotp_add_ecc == 1) {
		io_clrbits32((bcm_sotp_base + SOTP_PROG_CONTROL),
			     SOTP_PROG_CONTROL__OTP_DISABLE_ECC);
	} else {
		io_setbits32((bcm_sotp_base + SOTP_PROG_CONTROL),
			     SOTP_PROG_CONTROL__OTP_DISABLE_ECC);
	}

	/* 10 bit row address */
	reg_val = (row_addr & SOTP_ADDR_MASK) << SOTP_ADDR__OTP_ROW_ADDR_R;
	io_write32((bcm_sotp_base + SOTP_ADDR), reg_val);
	reg_val = SOTP_READ;
	io_write32((bcm_sotp_base + SOTP_CTRL_0), reg_val);

	/* Start bit to tell SOTP to send command to the OTP controller */
	io_setbits32((bcm_sotp_base + SOTP_CTRL_0), SOTP_CTRL_0__START);

	/* Wait for SOTP command done to be set */
	ret = otp_status_done_wait((bcm_sotp_base + SOTP_STAT_0),
				   SOTP_STATUS_1__CMD_DONE);
	if (ret) {
		EMSG("FDONE cmd done wait failed\n");
		return ret;
	}

	DMSG("CMD Done\n");

	/* Clr Start bit after command done */
	io_clrbits32((bcm_sotp_base + SOTP_CTRL_0), SOTP_CTRL_0__START);
	read_data = io_read32(bcm_sotp_base + SOTP_RDDATA_1);
	read_data = ((read_data & 0x1ff) << 32);
	read_data |= io_read32(bcm_sotp_base + SOTP_RDDATA_0);

	reg_val = io_read32(bcm_sotp_base + SOTP_STATUS_1);
	/* No ECC check till SOTP_NO_ECC_ROWS */
	if (row_addr > SOTP_NO_ECC_ROWS &&
	    reg_val & SOTP_STATUS_1__ECC_DET) {
		EMSG("SOTP ECC ERROR Detected ROW %d\n", row_addr);
		read_data = SOTP_ECC_ERR_DETECT;
	}

	/* Command done is cleared */
	io_setbits32((bcm_sotp_base + SOTP_STATUS_1), SOTP_STATUS_1__CMD_DONE);
	io_clrbits32((bcm_sotp_base + SOTP_PROG_CONTROL),
		     SOTP_PROG_CONTROL__OTP_CPU_MODE_EN);
	DMSG("read done\n");

	*rdata = read_data;
	return ret;
}

static TEE_Result bcm_sotp_init(void)
{
	bcm_sotp_base = (vaddr_t)phys_to_virt(SOTP_BASE, MEM_AREA_IO_SEC, 1);

	DMSG("bcm_sotp init done\n");
	return TEE_SUCCESS;
}

service_init(bcm_sotp_init);
