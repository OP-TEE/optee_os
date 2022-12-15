// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Microchip
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/i2c.h>
#include <drivers/pinctrl.h>
#include <io.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <matrix.h>
#include <platform_config.h>
#include <string.h>

#define TWIHS_CR		0x0
#define TWIHS_CR_SWRST		BIT(7)
#define TWIHS_CR_SVDIS		BIT(5)
#define TWIHS_CR_MSEN		BIT(2)
#define TWIHS_CR_STOP		BIT(1)
#define TWIHS_CR_START		BIT(0)

#define TWIHS_MMR		0x4
#define TWIHS_MMR_DADR_SHIFT	16
#define TWIHS_MMR_DADR_MASK	0x7F
#define TWIHS_MMR_MREAD		BIT32(12)

#define TWIHS_CWGR		0x10
#define TWIHS_CWGR_HOLD_SHIFT	24
#define TWIHS_CWGR_HOLD_MAX	0x1F
#define TWIHS_CWGR_CKDIV_SHIFT	16
#define TWIHS_CWGR_CKDIV_MAX	0x7
#define TWIHS_CWGR_CHDIV_SHIFT	8

#define TWIHS_CKSRC	BIT32(20)

#define TWIHS_SR	0x20
#define TWIHS_SR_NACK	BIT32(8)
#define TWIHS_SR_TXRDY	BIT32(2)
#define TWIHS_SR_RXRDY	BIT32(1)
#define TWIHS_SR_TXCOMP	BIT32(0)

#define TWIHS_RHR	0x30
#define TWIHS_THR	0x34

#define TWIHS_WPMR		0xE4
#define TWIHS_WPMR_WPKEY	SHIFT_U32(0x545749, 8)

#define I2C_BUS_FREQ	400000

struct atmel_i2c {
	uint32_t sda_hold_time;
	vaddr_t base;
	struct clk *clk;
};

static TEE_Result atmel_i2c_send_one_byte(struct atmel_i2c *i2c, uint8_t byte)
{
	uint32_t sr = 0;

	io_write32(i2c->base + TWIHS_THR, byte);

	while (1) {
		sr = io_read32(i2c->base + TWIHS_SR);
		if (sr & TWIHS_SR_NACK) {
			EMSG("Received NACK while writing !");
			return TEE_ERROR_GENERIC;
		}
		if (sr & TWIHS_SR_TXRDY)
			break;
	}

	return TEE_SUCCESS;
}

static void atmel_i2c_wait_txcomp(struct atmel_i2c *i2c)
{
	uint32_t sr = 0;

	while (1) {
		sr = io_read32(i2c->base + TWIHS_SR);
		if (sr & TWIHS_SR_TXCOMP)
			return;
	}
}

static void atmel_i2c_send_start(struct atmel_i2c *i2c)
{
	io_write32(i2c->base + TWIHS_CR, TWIHS_CR_START);
}

static void atmel_i2c_send_stop(struct atmel_i2c *i2c)
{
	io_write32(i2c->base + TWIHS_CR, TWIHS_CR_STOP);
}

static TEE_Result atmel_i2c_write_data_no_stop(struct i2c_dev *i2c_dev,
					       const uint8_t *buf, int len)
{
	int i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct atmel_i2c *i2c = i2c_dev->ctrl->priv;
	uint32_t mmr = SHIFT_U32(i2c_dev->addr, TWIHS_MMR_DADR_SHIFT);

	io_write32(i2c->base + TWIHS_MMR, mmr);

	for (i = 0; i < len; i++) {
		res = atmel_i2c_send_one_byte(i2c, buf[i]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result atmel_i2c_write_data(struct i2c_dev *i2c_dev,
				       const uint8_t *buf, int len)
{
	struct atmel_i2c *i2c = i2c_dev->ctrl->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = atmel_i2c_write_data_no_stop(i2c_dev, buf, len);
	if (res)
		return res;

	atmel_i2c_send_stop(i2c);
	atmel_i2c_wait_txcomp(i2c);

	return TEE_SUCCESS;
}

static TEE_Result atmel_i2c_recv_one_byte(struct atmel_i2c *i2c,
					  uint8_t *byte)
{
	uint32_t sr = 0;

	while (1) {
		sr = io_read32(i2c->base + TWIHS_SR);
		if (sr & TWIHS_SR_NACK) {
			EMSG("Received NACK while reading !");
			return TEE_ERROR_GENERIC;
		}
		if (sr & TWIHS_SR_RXRDY)
			break;
	}

	*byte = io_read32(i2c->base + TWIHS_RHR);

	return TEE_SUCCESS;
}

static TEE_Result atmel_i2c_read_data(struct i2c_dev *i2c_dev, uint8_t *buf,
				      int len)
{
	int i = 0;
	struct atmel_i2c *i2c = i2c_dev->ctrl->priv;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t mmr = TWIHS_MMR_MREAD | SHIFT_U32(i2c_dev->addr,
						   TWIHS_MMR_DADR_SHIFT);

	io_write32(i2c->base + TWIHS_MMR, mmr);

	atmel_i2c_send_start(i2c);

	for (i = 0; i < len; i++) {
		if (i == len - 1)
			atmel_i2c_send_stop(i2c);

		res = atmel_i2c_recv_one_byte(i2c, &buf[i]);
		if (res)
			return res;
	}

	atmel_i2c_wait_txcomp(i2c);

	return TEE_SUCCESS;
}

static TEE_Result atmel_i2c_smbus(struct i2c_dev *i2c_dev, uint8_t dir,
				  uint8_t proto __unused, uint8_t cmd_code,
				  uint8_t buf[I2C_SMBUS_MAX_BUF_SIZE],
				  unsigned int len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Send command code first */
	res = atmel_i2c_write_data_no_stop(i2c_dev, &cmd_code, 1);
	if (res)
		return res;

	if (dir == I2C_SMBUS_READ)
		return atmel_i2c_read_data(i2c_dev, buf, len);
	else
		return atmel_i2c_write_data(i2c_dev, buf, len);
}

static unsigned int flsi(unsigned int val)
{
	if (val == 0)
		return 0;

	return sizeof(unsigned int) * 8 - __builtin_clz(val);
}

static TEE_Result atmel_i2c_init_clk(struct atmel_i2c *i2c)
{
	unsigned long clk = clk_get_rate(i2c->clk);
	uint32_t cwgr = 0, cxdiv = 0, ckdiv = 0;
	long div = 0, hold = 0;

	/* Since we will configure both CHDIV and CLDIV with the same value
	 * use 2 * clk
	 */
	div = UDIV_ROUND_NEAREST(clk, 2 * I2C_BUS_FREQ) - 3;
	if (div < 0)
		div = 0;

	/* CHDIV/CLDIV are on 8 bits, CKDIV on 3 bits */
	ckdiv = flsi(div >> 8);
	if (ckdiv > TWIHS_CWGR_CKDIV_MAX) {
		EMSG("CKDIV value too large");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	cxdiv = div >> ckdiv;

	if (i2c->sda_hold_time) {
		/* hold_time = (HOLD + 3) x tperipheral clock */
		hold = UDIV_ROUND_NEAREST(i2c->sda_hold_time * clk, 1000000000);
		hold -= 3;
		if (hold < 0 || hold > TWIHS_CWGR_HOLD_MAX) {
			EMSG("Incorrect hold value");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		cwgr |= hold << TWIHS_CWGR_HOLD_SHIFT;
	}

	cwgr |= ckdiv << TWIHS_CWGR_CKDIV_SHIFT;
	/* CHDIV == CLDIV */
	cwgr |= cxdiv << TWIHS_CWGR_CHDIV_SHIFT;
	cwgr |= cxdiv;
	io_write32(i2c->base + TWIHS_CWGR, cwgr);

	return TEE_SUCCESS;
}

static TEE_Result atmel_i2c_init_hw(struct atmel_i2c *i2c)
{
	TEE_Result res = TEE_SUCCESS;

	/* Unlock TWIHS IP */
	io_write32(i2c->base + TWIHS_WPMR, TWIHS_WPMR_WPKEY);

	/* Configure master mode */
	io_write32(i2c->base + TWIHS_CR, TWIHS_CR_SWRST);

	io_write32(i2c->base + TWIHS_CR, TWIHS_CR_SVDIS);
	io_write32(i2c->base + TWIHS_CR, TWIHS_CR_MSEN);

	res = atmel_i2c_init_clk(i2c);
	if (res)
		return res;

	return TEE_SUCCESS;
}

static struct i2c_ctrl_ops atmel_i2c_ops = {
	.read = atmel_i2c_read_data,
	.write = atmel_i2c_write_data,
	.smbus = atmel_i2c_smbus,
};

static TEE_Result atmel_i2c_node_probe(const void *fdt, int node,
				       const void *compat_data __unused,
				       const struct dt_driver *dt_drv __unused)
{
	int status = _fdt_get_status(fdt, node);
	size_t size = 0;
	const uint32_t *cuint = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int matrix_id = 0;
	struct atmel_i2c *atmel_i2c = NULL;
	struct i2c_ctrl *i2c_ctrl = NULL;

	if (status != DT_STATUS_OK_SEC)
		return TEE_SUCCESS;

	res = pinctrl_apply_state(fdt, node, NULL);
	if (res)
		return res;

	i2c_ctrl = calloc(1,
			  sizeof(struct i2c_ctrl) + sizeof(struct atmel_i2c));
	if (!i2c_ctrl)
		return TEE_ERROR_OUT_OF_MEMORY;

	atmel_i2c = (struct atmel_i2c *)(i2c_ctrl + 1);
	i2c_ctrl->priv = atmel_i2c;
	i2c_ctrl->ops = &atmel_i2c_ops;

	res = clk_dt_get_by_index(fdt, node, 0, &atmel_i2c->clk);
	if (res)
		return res;

	res = matrix_dt_get_id(fdt, node, &matrix_id);
	if (res)
		return res;

	if (dt_map_dev(fdt, node, &atmel_i2c->base, &size, DT_MAP_AUTO) < 0)
		return TEE_ERROR_GENERIC;

	matrix_configure_periph_secure(matrix_id);

	clk_enable(atmel_i2c->clk);

	cuint = fdt_getprop(fdt, node, "i2c-sda-hold-time-ns", NULL);
	if (cuint)
		atmel_i2c->sda_hold_time = fdt32_to_cpu(*cuint);

	res = atmel_i2c_init_hw(atmel_i2c);
	if (res)
		return res;

	i2c_ctrl_register(i2c_ctrl, fdt, node);

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_i2c_match_table[] = {
	{ .compatible = "atmel,sama5d2-i2c" },
	{ }
};

DEFINE_DT_DRIVER(atmel_i2c_dt_driver) = {
	.name = "atmel_i2c",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_i2c_match_table,
	.probe = atmel_i2c_node_probe,
};
