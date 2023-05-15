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

#define SOTP_PROG_CONTROL		0x00
#define SOTP_WRDATA_0			0x04
#define SOTP_WRDATA_1			0x08
#define SOTP_ADDR			0x0c
#define SOTP_CTRL_0			0x10
#define SOTP_STAT_0			0x18
#define SOTP_STATUS_1			0x1c
#define SOTP_RDDATA_0			0x20
#define SOTP_RDDATA_1			0x24
#define SOTP_REGS_SOTP_CHIP_STATES	0x28
#define SOTP_REGS_OTP_WR_LOCK		0x38
#define SOTP_CHIP_CTRL			0x4c

#define SOTP_PROG_CONTROL__OTP_CPU_MODE_EN	BIT(15)
#define SOTP_PROG_CONTROL__OTP_DISABLE_ECC	BIT(9)
#define SOTP_ADDR__OTP_ROW_ADDR_R		6
#define SOTP_PROG_CONTROL__OTP_ECC_WREN		BIT(8)
#define SOTP_CTRL_0__START			1
#define SOTP_STATUS_0__FDONE			BIT(3)
#define SOTP_STATUS_1__CMD_DONE			BIT(1)
#define SOTP_STATUS_1__ECC_DET			BIT(17)

#define SOTP_READ				0
#define SOTP_ADDR_MASK				0x3ff
#define SOTP_TIMEOUT_US				300

#define SOTP_PROG_WORD				10
#define SOTP_STATUS__PROGOK			BIT(2)
#define SOTP_PROG_ENABLE			2

#define SOTP_ROW_DATA_MASK			UINT32_MAX
#define SOTP_ECC_ERR_BITS_MASK			GENMASK_64(40, 32)

#define SOTP_CHIP_CTRL_SW_OVERRIDE_CHIP_STATES	4
#define SOTP_CHIP_CTRL_SW_MANU_PROG		5
#define SOTP_CHIP_CTRL_SW_CID_PROG		6
#define SOTP_CHIP_CTRL_SW_AB_DEVICE		8
#define SOTP_CHIP_CTRL_SW_AB_DEV_MODE		9
#define CHIP_STATE_UNPROGRAMMED			0x1
#define CHIP_STATE_UNASSIGNED			0x2
#define CHIP_STATE_DEFAULT			(CHIP_STATE_UNASSIGNED | \
						 CHIP_STATE_UNPROGRAMMED)

static vaddr_t bcm_sotp_base;

static TEE_Result otp_status_done_wait(vaddr_t addr, uint32_t bit)
{
	uint64_t timeout = timeout_init_us(SOTP_TIMEOUT_US);

	while (!(io_read32(addr) & bit))
		if (timeout_elapsed(timeout))
			return TEE_ERROR_BUSY;
	return TEE_SUCCESS;
}

TEE_Result bcm_iproc_sotp_mem_read(uint32_t row_addr, bool sotp_add_ecc,
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
		EMSG("FDONE status done wait failed and returned %#"PRIx32,
		     ret);
		return ret;
	}

	/* Enable OTP access by CPU */
	io_setbits32((bcm_sotp_base + SOTP_PROG_CONTROL),
		     SOTP_PROG_CONTROL__OTP_CPU_MODE_EN);

	/* ROWS does not support ECC */
	if (row_addr <= SOTP_NO_ECC_ROWS)
		sotp_add_ecc = false;

	if (sotp_add_ecc) {
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
		EMSG("FDONE cmd done wait failed and returned %#"PRIx32, ret);
		return ret;
	}

	DMSG("CMD Done");

	/* Clr Start bit after command done */
	io_clrbits32((bcm_sotp_base + SOTP_CTRL_0), SOTP_CTRL_0__START);
	read_data = io_read32(bcm_sotp_base + SOTP_RDDATA_1);
	read_data = ((read_data & 0x1ff) << 32);
	read_data |= io_read32(bcm_sotp_base + SOTP_RDDATA_0);

	reg_val = io_read32(bcm_sotp_base + SOTP_STATUS_1);
	/* No ECC check till SOTP_NO_ECC_ROWS */
	if (row_addr > SOTP_NO_ECC_ROWS &&
	    reg_val & SOTP_STATUS_1__ECC_DET) {
		EMSG("SOTP ECC ERROR Detected ROW %"PRIu32, row_addr);
		read_data = SOTP_ECC_ERR_DETECT;
	}

	/* Command done is cleared */
	io_setbits32((bcm_sotp_base + SOTP_STATUS_1), SOTP_STATUS_1__CMD_DONE);
	io_clrbits32((bcm_sotp_base + SOTP_PROG_CONTROL),
		     SOTP_PROG_CONTROL__OTP_CPU_MODE_EN);
	DMSG("read done");

	*rdata = read_data;
	return ret;
}

TEE_Result bcm_iproc_sotp_mem_write(uint32_t row_addr, bool sotp_add_ecc,
				    uint64_t wdata)
{
	uint32_t chip_state = 0;
	uint32_t chip_ctrl_default = 0;
	uint32_t chip_ctrl = 0;
	uint32_t loop = 0;
	uint8_t prog_array[4] = { 0x0F, 0x04, 0x08, 0x0D };
	TEE_Result ret = TEE_SUCCESS;

	assert(bcm_sotp_base);

	chip_state = io_read32(bcm_sotp_base + SOTP_REGS_SOTP_CHIP_STATES);

	if (chip_state & CHIP_STATE_DEFAULT) {
		chip_ctrl_default = io_read32(bcm_sotp_base + SOTP_CHIP_CTRL);
		DMSG("SOTP: enable special prog mode");

		chip_ctrl = BIT(SOTP_CHIP_CTRL_SW_OVERRIDE_CHIP_STATES) |
			    BIT(SOTP_CHIP_CTRL_SW_MANU_PROG) |
			    BIT(SOTP_CHIP_CTRL_SW_CID_PROG) |
			    BIT(SOTP_CHIP_CTRL_SW_AB_DEVICE);

		io_write32(bcm_sotp_base + SOTP_CHIP_CTRL, chip_ctrl);
	}

	/* Check for FDONE status */
	ret = otp_status_done_wait(bcm_sotp_base + SOTP_STAT_0,
				   SOTP_STATUS_0__FDONE);
	if (ret) {
		EMSG("FDONE status done wait failed and returned %#"PRIx32,
		     ret);
		return ret;
	}

	/* Enable OTP access by CPU */
	io_setbits32(bcm_sotp_base + SOTP_PROG_CONTROL,
		     SOTP_PROG_CONTROL__OTP_CPU_MODE_EN);

	if (row_addr <= SOTP_NO_ECC_ROWS) {
		if (sotp_add_ecc) {
			io_setbits32(bcm_sotp_base + SOTP_PROG_CONTROL,
				     SOTP_PROG_CONTROL__OTP_ECC_WREN);
		} else {
			io_clrbits32(bcm_sotp_base + SOTP_PROG_CONTROL,
				     SOTP_PROG_CONTROL__OTP_ECC_WREN);
		}
	} else {
		io_clrbits32(bcm_sotp_base + SOTP_PROG_CONTROL,
			     SOTP_PROG_CONTROL__OTP_ECC_WREN);
	}

	io_write32(bcm_sotp_base + SOTP_CTRL_0, SOTP_PROG_ENABLE << 1);

	/*
	 * In order to avoid unintentional writes/programming of the OTP array,
	 * the OTP Controller must be put into programming mode before it will
	 * accept program commands. This is done by writing 0xF, 0x4, 0x8, 0xD
	 * with program commands prior to starting the actual programming
	 * sequence.
	 */
	for (loop = 0; loop < ARRAY_SIZE(prog_array); loop++) {
		io_write32(bcm_sotp_base + SOTP_WRDATA_0, prog_array[loop]);

		/* Bit to tell SOTP to send command to the OTP controller */
		io_setbits32(bcm_sotp_base + SOTP_CTRL_0, SOTP_CTRL_0__START);

		/*  Wait for SOTP command done to be set */
		ret = otp_status_done_wait(bcm_sotp_base + SOTP_STATUS_1,
					   SOTP_STATUS_1__CMD_DONE);
		if (ret) {
			EMSG("FDONE cmd done wait failed and returned %"PRIx32,
			     ret);
			return ret;
		}

		/* Command done is cleared w1c */
		io_setbits32(bcm_sotp_base + SOTP_STATUS_1,
			     SOTP_STATUS_1__CMD_DONE);

		/* Clear Start bit after command done */
		io_clrbits32(bcm_sotp_base + SOTP_CTRL_0, SOTP_CTRL_0__START);
	}

	/* Check for PROGOK */
	ret = otp_status_done_wait(bcm_sotp_base + SOTP_STAT_0,
				   SOTP_STATUS__PROGOK);
	if (ret) {
		EMSG("PROGOK cmd wait failed and returned %#"PRIx32, ret);
		return ret;
	}

	/* Set 10 bit row address */
	io_write32(bcm_sotp_base + SOTP_ADDR,
		   (row_addr & SOTP_ADDR_MASK) << SOTP_ADDR__OTP_ROW_ADDR_R);

	/* Set SOTP Row data */
	io_write32(bcm_sotp_base + SOTP_WRDATA_0, wdata & SOTP_ROW_DATA_MASK);

	/* Set SOTP ECC and error bits */
	io_write32(bcm_sotp_base + SOTP_WRDATA_1,
		   (wdata & SOTP_ECC_ERR_BITS_MASK) >> 32);

	/* Set prog_word command */
	io_write32(bcm_sotp_base + SOTP_CTRL_0, SOTP_PROG_WORD << 1);

	/* Start bit to tell SOTP to send command to the OTP controller */
	io_setbits32(bcm_sotp_base + SOTP_CTRL_0, SOTP_CTRL_0__START);

	/* Wait for SOTP command done to be set */
	ret = otp_status_done_wait(bcm_sotp_base + SOTP_STATUS_1,
				   SOTP_STATUS_1__CMD_DONE);
	if (ret) {
		EMSG("CMD DONE wait failed and returned %#"PRIx32, ret);
		return ret;
	}

	/* Command done is cleared w1c */
	io_setbits32(bcm_sotp_base + SOTP_STATUS_1, SOTP_STATUS_1__CMD_DONE);

	/* disable OTP access by CPU */
	io_clrbits32(bcm_sotp_base + SOTP_PROG_CONTROL,
		     SOTP_PROG_CONTROL__OTP_CPU_MODE_EN);

	/* Clr Start bit after command done */
	io_clrbits32(bcm_sotp_base + SOTP_CTRL_0, SOTP_CTRL_0__START);

	if (chip_state & CHIP_STATE_DEFAULT)
		io_write32(bcm_sotp_base + SOTP_CHIP_CTRL, chip_ctrl_default);

	return TEE_SUCCESS;
}

static TEE_Result bcm_sotp_init(void)
{
	bcm_sotp_base = (vaddr_t)phys_to_virt(SOTP_BASE, MEM_AREA_IO_SEC, 1);

	DMSG("bcm_sotp init done");
	return TEE_SUCCESS;
}

service_init(bcm_sotp_init);
