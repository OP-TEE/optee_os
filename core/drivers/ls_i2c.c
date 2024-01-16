// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * I2C driver for I2C Controller
 *
 */
#include <assert.h>
#include <drivers/ls_i2c.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/delay.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <string.h>

static const char * const i2c_controller_map[] = {
	"/soc/i2c@2000000", "/soc/i2c@2010000", "/soc/i2c@2020000",
	"/soc/i2c@2030000", "/soc/i2c@2040000", "/soc/i2c@2050000",
	"/soc/i2c@2060000", "/soc/i2c@2070000"
};

/*
 * I2C divisor and ibfd register values when glitch filter is enabled
 * In case of duplicate SCL divisor value, the ibfd value with high MUL value
 * has been selected. A higher MUL value results in a lower sampling rate of
 * the I2C signals. This gives the I2C module greater immunity against glitches
 * in the I2C signals.
 */
static const struct i2c_clock_divisor_pair clk_div_glitch_enabled[] = {
	{ 34, 0x0 },	 { 36, 0x1 },	  { 38, 0x2 },	  { 40, 0x3 },
	{ 42, 0x4 },	 { 44, 0x8 },	  { 48, 0x9 },	  { 52, 0xA },
	{ 54, 0x7 },	 { 56, 0xB },	  { 60, 0xC },	  { 64, 0x10 },
	{ 68, 0x40 },	 { 72, 0x41 },	  { 76, 0x42 },	  { 80, 0x43 },
	{ 84, 0x44 },	 { 88, 0x48 },	  { 96, 0x49 },	  { 104, 0x4A },
	{ 108, 0x47 },	 { 112, 0x4B },	  { 120, 0x4C },  { 128, 0x50 },
	{ 136, 0x80 },	 { 144, 0x81 },	  { 152, 0x82 },  { 160, 0x83 },
	{ 168, 0x84 },	 { 176, 0x88 },	  { 192, 0x89 },  { 208, 0x8A },
	{ 216, 0x87 },	 { 224, 0x8B },	  { 240, 0x8C },  { 256, 0x90 },
	{ 288, 0x91 },	 { 320, 0x92 },	  { 336, 0x8F },  { 352, 0x93 },
	{ 384, 0x98 },	 { 416, 0x95 },	  { 448, 0x99 },  { 480, 0x96 },
	{ 512, 0x9A },	 { 576, 0x9B },	  { 640, 0xA0 },  { 704, 0x9D },
	{ 768, 0xA1 },	 { 832, 0x9E },	  { 896, 0xA2 },  { 960, 0x67 },
	{ 1024, 0xA3 },	 { 1152, 0xA4 },  { 1280, 0xA8 }, { 1536, 0xA9 },
	{ 1792, 0xAA },	 { 1920, 0xA7 },  { 2048, 0xAB }, { 2304, 0xAC },
	{ 2560, 0xB0 },	 { 3072, 0xB1 },  { 3584, 0xB2 }, { 3840, 0xAF },
	{ 4096, 0xB3 },	 { 4608, 0xB4 },  { 5120, 0xB8 }, { 6144, 0xB9 },
	{ 7168, 0xBA },	 { 7680, 0xB7 },  { 8192, 0xBB }, { 9216, 0xBC },
	{ 10240, 0xBD }, { 12288, 0xBE }, { 15360, 0xBF }
};

/*
 * I2C divisor and ibfd register values when glitch filter is disabled.
 * In case of duplicate SCL divisor value, the ibfd value with high MUL value
 * has been selected. A higher MUL value results in a lower sampling rate of
 * the I2C signals. This gives the I2C module greater immunity against glitches
 * in the I2C signals.
 */
static const struct i2c_clock_divisor_pair clk_div_glitch_disabled[] = {
	{ 20, 0x0 },	 { 22, 0x1 },	  { 24, 0x2 },	  { 26, 0x3 },
	{ 28, 0x8 },	 { 30, 0x5 },	  { 32, 0x9 },	  { 34, 0x6 },
	{ 36, 0x0A },	 { 40, 0x40 },	  { 44, 0x41 },	  { 48, 0x42 },
	{ 52, 0x43 },	 { 56, 0x48 },	  { 60, 0x45 },	  { 64, 0x49 },
	{ 68, 0x46 },	 { 72, 0x4A },	  { 80, 0x80 },	  { 88, 0x81 },
	{ 96, 0x82 },	 { 104, 0x83 },	  { 112, 0x88 },  { 120, 0x85 },
	{ 128, 0x89 },	 { 136, 0x86 },	  { 144, 0x8A },  { 160, 0x8B },
	{ 176, 0x8C },	 { 192, 0x90 },	  { 208, 0x56 },  { 224, 0x91 },
	{ 240, 0x1F },	 { 256, 0x92 },	  { 272, 0x8F },  { 288, 0x93 },
	{ 320, 0x98 },	 { 352, 0x95 },	  { 384, 0x99 },  { 416, 0x96 },
	{ 448, 0x9A },	 { 480, 0x5F },	  { 512, 0x9B },  { 576, 0x9C },
	{ 640, 0xA0 },	 { 768, 0xA1 },	  { 896, 0xA2 },  { 960, 0x9F },
	{ 1024, 0xA3 },	 { 1152, 0xA4 },  { 1280, 0xA8 }, { 1536, 0xA9 },
	{ 1792, 0xAA },	 { 1920, 0xA7 },  { 2048, 0xAB }, { 2304, 0xAC },
	{ 2560, 0xAD },	 { 3072, 0xB1 },  { 3584, 0xB2 }, { 3840, 0xAF },
	{ 4096, 0xB3 },	 { 4608, 0xB4 },  { 5120, 0xB8 }, { 6144, 0xB9 },
	{ 7168, 0xBA },	 { 7680, 0xB7 },  { 8192, 0xBB }, { 9216, 0xBC },
	{ 10240, 0xBD }, { 12288, 0xBE }, { 15360, 0xBF }
};

void i2c_reset(vaddr_t base)
{
	struct i2c_regs *regs = (struct i2c_regs *)base;

	io_setbits8((vaddr_t)&regs->ibcr, I2C_IBCR_MDIS);
	io_setbits8((vaddr_t)&regs->ibsr, I2C_IBSR_IBAL | I2C_IBSR_IBIF);
	io_clrbits8((vaddr_t)&regs->ibcr, I2C_IBCR_IBIE | I2C_IBCR_DMAEN);
	io_clrbits8((vaddr_t)&regs->ibic, I2C_IBIC_BIIE);
}

/*
 * Get I2c Bus Frequency Divider Register value based on clock_divisor
 * and if the glitch is enabled or not in I2c controller.
 * base			Base address of I2C controller
 * clock_divisor	Clock Divisor
 */
static uint8_t i2c_get_ibfd(vaddr_t base, uint16_t clock_divisor)
{
	struct i2c_regs *regs = (struct i2c_regs *)base;
	const struct i2c_clock_divisor_pair *dpair = NULL;
	size_t dpair_sz = 0;
	unsigned int n = 0;

	if (io_read8((vaddr_t)&regs->ibdbg) & I2C_IBDBG_GLFLT_EN) {
		dpair = clk_div_glitch_enabled;
		dpair_sz = ARRAY_SIZE(clk_div_glitch_enabled);
	} else {
		dpair = clk_div_glitch_disabled;
		dpair_sz = ARRAY_SIZE(clk_div_glitch_disabled);
	}

	for (n = 0; n < dpair_sz - 1; n++)
		if (clock_divisor < dpair[n].divisor)
			break;

	return dpair[n].ibfd;
}

TEE_Result i2c_init(struct ls_i2c_data *i2c_data)
{
	struct i2c_regs *regs = NULL;
	uint16_t clock_divisor = 0;
	uint8_t ibfd = 0; /* I2c Bus Frequency Divider Register */
	size_t size = 0;
	int node = 0;
	vaddr_t ctrl_base = 0;
	void *fdt = NULL;

	/*
	 * First get the I2C Controller base address from the DTB
	 * if DTB present and if the I2C Controller defined in it.
	 */
	fdt = get_embedded_dt();
	if (!fdt) {
		EMSG("Unable to get the Embedded DTB, I2C init failed");
		return TEE_ERROR_GENERIC;
	}

	node = fdt_path_offset(fdt,
			       i2c_controller_map[i2c_data->i2c_controller]);
	if (node > 0) {
		if (dt_map_dev(fdt, node, &ctrl_base, &size,
			       DT_MAP_AUTO) < 0) {
			EMSG("Unable to get virtual address");
			return TEE_ERROR_GENERIC;
		}
	} else {
		EMSG("Unable to get I2C offset node");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	i2c_data->base = ctrl_base;

	regs = (struct i2c_regs *)ctrl_base;

	clock_divisor = (i2c_data->i2c_bus_clock + i2c_data->speed - 1) /
			i2c_data->speed;
	ibfd = i2c_get_ibfd(ctrl_base, clock_divisor);

	io_write8((vaddr_t)&regs->ibfd, ibfd);

	i2c_reset(ctrl_base);

	return TEE_SUCCESS;
}

/*
 * Check if I2C bus is busy with previous transaction or not.
 * regs         pointer to I2c controller registers
 * test_busy	this flag tells if we need to check the busy bit in IBSR reg
 */
static TEE_Result i2c_bus_test_bus_busy(struct i2c_regs *regs, bool test_busy)
{
	unsigned int n = 0;
	uint8_t reg = 0;

	for (n = 0; n < I2C_NUM_RETRIES; n++) {
		reg = io_read8((vaddr_t)&regs->ibsr);

		if (reg & I2C_IBSR_IBAL) {
			io_write8((vaddr_t)&regs->ibsr, reg);
			return TEE_ERROR_BUSY;
		}

		if (test_busy && (reg & I2C_IBSR_IBB))
			break;

		if (!test_busy && !(reg & I2C_IBSR_IBB))
			break;

		mdelay(1);
	}

	if (n == I2C_NUM_RETRIES)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

/*
 * Check if data transfer to/from i2c controller is complete.
 * regs		pointer to I2c controller registers
 * test_rx_ack	this flag tells if we need to check RXAK bit in IBSR reg
 */
static TEE_Result i2c_transfer_complete(struct i2c_regs *regs, bool test_rx_ack)
{
	unsigned int n = 0;
	uint8_t reg = 0;

	for (n = 0; n < I2C_NUM_RETRIES; n++) {
		reg = io_read8((vaddr_t)&regs->ibsr);

		if (reg & I2C_IBSR_IBIF) {
			/* Write 1 to clear the IBIF field */
			io_write8((vaddr_t)&regs->ibsr, reg);
			break;
		}
		mdelay(1);
	}

	if (n == I2C_NUM_RETRIES)
		return TEE_ERROR_BUSY;

	if (test_rx_ack && (reg & I2C_IBSR_RXAK))
		return TEE_ERROR_NO_DATA;

	if (reg & I2C_IBSR_TCF)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}

/*
 * Read data from I2c controller.
 * regs			pointer to I2c controller registers
 * slave_address	slave address from which to read
 * operation		pointer to i2c_operation struct
 * is_last_operation	if current operation is last operation
 */
static TEE_Result i2c_read(struct i2c_regs *regs, unsigned int slave_address,
			   struct i2c_operation *operation,
			   bool is_last_operation)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int n = 0;

	/* Write Slave Address */
	io_write8((vaddr_t)&regs->ibdr, (slave_address << 0x1) | BIT(0));
	res = i2c_transfer_complete(regs, I2C_BUS_TEST_RX_ACK);
	if (res)
		return res;

	/* select Receive mode. */
	io_clrbits8((vaddr_t)&regs->ibcr, I2C_IBCR_TXRX);
	if (operation->length_in_bytes > 1) {
		/* Set No ACK = 0 */
		io_clrbits8((vaddr_t)&regs->ibcr, I2C_IBCR_NOACK);
	}

	/* Perform a dummy read to initiate the receive operation. */
	io_read8((vaddr_t)&regs->ibdr);

	for (n = 0; n < operation->length_in_bytes; n++) {
		res = i2c_transfer_complete(regs, I2C_BUS_NO_TEST_RX_ACK);
		if (res)
			return res;
		if (n == (operation->length_in_bytes - 2)) {
			/* Set No ACK = 1 */
			io_setbits8((vaddr_t)&regs->ibcr, I2C_IBCR_NOACK);
		} else if (n == (operation->length_in_bytes - 1)) {
			if (!is_last_operation) {
				/* select Transmit mode (for repeat start) */
				io_setbits8((vaddr_t)&regs->ibcr,
					    I2C_IBCR_TXRX);
			} else {
				/* Generate Stop Signal */
				io_clrbits8((vaddr_t)&regs->ibcr,
					    (I2C_IBCR_MSSL | I2C_IBCR_TXRX));
				res = i2c_bus_test_bus_busy(regs,
							    I2C_BUS_TEST_IDLE);
				if (res)
					return res;
			}
		}
		operation->buffer[n] = io_read8((vaddr_t)&regs->ibdr);
	}

	return TEE_SUCCESS;
}

/*
 * Write data to I2c controller
 * regs			pointer to I2c controller registers
 * slave_address	slave address from which to read
 * operation		pointer to i2c_operation struct
 */
static TEE_Result i2c_write(struct i2c_regs *regs, unsigned int slave_address,
			    struct i2c_operation *operation)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int n = 0;

	/* Write Slave Address */
	io_write8((vaddr_t)&regs->ibdr,
		  (slave_address << 0x1) & ~(BIT(0)));
	res = i2c_transfer_complete(regs, I2C_BUS_TEST_RX_ACK);
	if (res)
		return res;

	/* Write Data */
	for (n = 0; n < operation->length_in_bytes; n++) {
		io_write8((vaddr_t)&regs->ibdr, operation->buffer[n]);
		res = i2c_transfer_complete(regs, I2C_BUS_TEST_RX_ACK);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

/*
 * Generate Stop Signal and disable I2C controller.
 * regs		pointer to I2c controller registers
 */
static TEE_Result i2c_stop(struct i2c_regs *regs)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t reg = 0;

	reg = io_read8((vaddr_t)&regs->ibsr);
	if (reg & I2C_IBSR_IBB) {
		/* Generate Stop Signal */
		io_clrbits8((vaddr_t)&regs->ibcr,
			    I2C_IBCR_MSSL | I2C_IBCR_TXRX);
		res = i2c_bus_test_bus_busy(regs, I2C_BUS_TEST_IDLE);
		if (res)
			return res;
	}

	/* Disable I2c Controller */
	io_setbits8((vaddr_t)&regs->ibcr, I2C_IBCR_MDIS);

	return TEE_SUCCESS;
}

/*
 * Generate Start Signal and set I2C controller in transmit mode.
 * regs		pointer to I2c controller registers
 */
static TEE_Result i2c_start(struct i2c_regs *regs)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	io_setbits8((vaddr_t)&regs->ibsr, I2C_IBSR_IBAL | I2C_IBSR_IBIF);
	io_clrbits8((vaddr_t)&regs->ibcr, I2C_IBCR_MDIS);

	/* Wait controller to be stable */
	mdelay(1);

	/* Generate Start Signal */
	io_setbits8((vaddr_t)&regs->ibcr, I2C_IBCR_MSSL);
	res = i2c_bus_test_bus_busy(regs, I2C_BUS_TEST_BUSY);
	if (res)
		return res;

	/* Select Transmit Mode. set No ACK = 1 */
	io_setbits8((vaddr_t)&regs->ibcr, I2C_IBCR_TXRX | I2C_IBCR_NOACK);

	return TEE_SUCCESS;
}

TEE_Result i2c_bus_xfer(vaddr_t base, unsigned int slave_address,
			struct i2c_operation *i2c_operation,
			unsigned int operation_count)
{
	unsigned int n = 0;
	struct i2c_regs *regs = (struct i2c_regs *)base;
	struct i2c_operation *operation = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_last_operation = false;

	res = i2c_bus_test_bus_busy(regs, I2C_BUS_TEST_IDLE);
	if (res)
		goto out;

	res = i2c_start(regs);
	if (res)
		goto out;

	for (n = 0, operation = i2c_operation;
	     n < operation_count; n++, operation++) {
		if (n == (operation_count - 1))
			is_last_operation = true;

		/* Send repeat start after first transmit/receive */
		if (n) {
			io_setbits8((vaddr_t)&regs->ibcr, I2C_IBCR_RSTA);
			res = i2c_bus_test_bus_busy(regs, I2C_BUS_TEST_BUSY);
			if (res)
				goto out;
		}

		/* Read/write data */
		if (operation->flags & I2C_FLAG_READ)
			res = i2c_read(regs, slave_address, operation,
				       is_last_operation);
		else
			res = i2c_write(regs, slave_address, operation);
		if (res)
			goto out;
	}

out:
	i2c_stop(regs);

	return res;
}
