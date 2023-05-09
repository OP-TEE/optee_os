// SPDX-License-Identifier: BSD-2-Clause
/*
 * (c) 2020 Jorge Ramirez <jorge@foundries.io>, Foundries Ltd.
 */
#include <arm.h>
#include <drivers/imx_i2c.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <trace.h>
#include <util.h>

#define I2C_CLK_RATE	24000000 /* Bits per second */

/* Utility macros (__x identifies the bus [1 .. 3]) */
#define I2C_CFG_SCL(__x)	(IOMUXC_I2C1_SCL_CFG_OFF + ((__x) - 1) * 0x8)
#define I2C_CFG_SDA(__x)	(IOMUXC_I2C1_SDA_CFG_OFF + ((__x) - 1) * 0x8)
#define I2C_MUX_SCL(__x)	(IOMUXC_I2C1_SCL_MUX_OFF + ((__x) - 1) * 0x8)
#define I2C_MUX_SDA(__x)	(IOMUXC_I2C1_SDA_MUX_OFF + ((__x) - 1) * 0x8)
#if defined(CFG_MX8MM) || defined(CFG_MX8MQ) || defined(CFG_MX8MP) || \
	defined(CFG_MX8MN)
/* IOMUX */
#define I2C_INP_SCL(__x)	0 /* Not implemented */
#define I2C_INP_SDA(__x)	0 /* Not implemented */
#define I2C_INP_VAL(__x)	0 /* Not implemented */
#define I2C_MUX_VAL(__x)	0x010
#define I2C_CFG_VAL(__x)	0x1c3
/* Clock */
#define I2C_CLK_CGRBM(__x)	0 /* Not implemented */
#define I2C_CLK_CGR6BM(__x)	0
#define I2C_CLK_CGR(__x)	CCM_CCRG_I2C##__x
#elif defined(CFG_MX6ULL)
/* IOMUX */
#define I2C_INP_SCL(__x)	(IOMUXC_I2C1_SCL_INP_OFF + ((__x) - 1) * 0x8)
#define I2C_INP_SDA(__x)	(IOMUXC_I2C1_SDA_INP_OFF + ((__x) - 1) * 0x8)
#define I2C_INP_VAL(__x)	(((__x) == 1) ? 0x1 : 0x2)
#define I2C_MUX_VAL(__x)	0x012
#define I2C_CFG_VAL(__x)	0x1b8b0
/* Clock */
#define I2C_CLK_CGRBM(__x)	BM_CCM_CCGR2_I2C##__x##_SERIAL
#define I2C_CLK_CGR6BM(__x)	BM_CCM_CCGR6_I2C##__x##_SERIAL
#define I2C_CLK_CGR(__x)	(((__x) == 4) ? CCM_CCGR6 : CCM_CCGR2)
#else
#error IMX_I2C driver not supported on this platform
#endif

#if !defined(CFG_MX8MP)
static struct io_pa_va i2c_bus[4] = {
#if !defined(CFG_DT) || defined(CFG_EXTERNAL_DTB_OVERLAY)
#if defined(I2C1_BASE)
	[0] = { .pa = I2C1_BASE, },
#endif
#if defined(I2C2_BASE)
	[1] = { .pa = I2C2_BASE, },
#endif
#if defined(I2C3_BASE)
	[2] = { .pa = I2C3_BASE, },
#endif
#if defined(I2C4_BASE)
	[3] = { .pa = I2C4_BASE, },
#endif
#endif
};
#else
static struct io_pa_va i2c_bus[6] = {
#if !defined(CFG_DT) || defined(CFG_EXTERNAL_DTB_OVERLAY)
#if defined(I2C1_BASE)
	[0] = { .pa = I2C1_BASE, },
#endif
#if defined(I2C2_BASE)
	[1] = { .pa = I2C2_BASE, },
#endif
#if defined(I2C3_BASE)
	[2] = { .pa = I2C3_BASE, },
#endif
#if defined(I2C4_BASE)
	[3] = { .pa = I2C4_BASE, },
#endif
#if defined(I2C5_BASE)
	[4] = { .pa = I2C5_BASE, },
#endif
#if defined(I2C6_BASE)
	[5] = { .pa = I2C6_BASE, },
#endif

#endif
};
#endif

static struct imx_i2c_clk {
	struct io_pa_va base;
	uint32_t i2c[ARRAY_SIZE(i2c_bus)];
	uint32_t cgrbm[ARRAY_SIZE(i2c_bus)];
} i2c_clk = {
	.base.pa = CCM_BASE,
	.i2c = { I2C_CLK_CGR(1), I2C_CLK_CGR(2), I2C_CLK_CGR(3), I2C_CLK_CGR(4), },
	.cgrbm = { I2C_CLK_CGRBM(1), I2C_CLK_CGRBM(2), I2C_CLK_CGRBM(3), I2C_CLK_CGR6BM(4),},
};

static struct imx_i2c_mux {
	struct io_pa_va base;
	struct imx_i2c_mux_regs {
		uint32_t scl_mux;
		uint32_t scl_cfg;
		uint32_t scl_inp;
		uint32_t sda_mux;
		uint32_t sda_cfg;
		uint32_t sda_inp;
	} i2c[ARRAY_SIZE(i2c_bus)];
} i2c_mux = {
	.base.pa = IOMUXC_BASE,
	.i2c = {{ .scl_mux = I2C_MUX_SCL(1), .scl_cfg = I2C_CFG_SCL(1),
		.scl_inp = I2C_INP_SCL(1), .sda_mux = I2C_MUX_SDA(1),
		.sda_cfg = I2C_CFG_SDA(1), .sda_inp = I2C_INP_SDA(1), },
		{ .scl_mux = I2C_MUX_SCL(2), .scl_cfg = I2C_CFG_SCL(2),
		.scl_inp = I2C_INP_SCL(2), .sda_mux = I2C_MUX_SDA(2),
		.sda_cfg = I2C_CFG_SDA(2), .sda_inp = I2C_INP_SDA(2), },
		{ .scl_mux = I2C_MUX_SCL(3), .scl_cfg = I2C_CFG_SCL(3),
		.scl_inp = I2C_INP_SCL(3), .sda_mux = I2C_MUX_SDA(3),
		.sda_cfg = I2C_CFG_SDA(3), .sda_inp = I2C_INP_SDA(3), },
		{ .scl_mux = I2C_MUX_SCL(4), .scl_cfg = I2C_CFG_SCL(4),
		.scl_inp = I2C_INP_SCL(4), .sda_mux = I2C_MUX_SDA(4),
		.sda_cfg = I2C_CFG_SDA(4), .sda_inp = I2C_INP_SDA(4), },},
};

#define I2DR				0x10
#define I2SR				0x0C
#define I2CR				0x08
#define IFDR				0x04

#define I2CR_IEN			BIT(7)
#define I2CR_IIEN			BIT(6)
#define I2CR_MSTA			BIT(5)
#define I2CR_MTX			BIT(4)
#define I2CR_TX_NO_AK			BIT(3)
#define I2CR_RSTA			BIT(2)

#define I2SR_ICF			BIT(7)
#define I2SR_IBB			BIT(5)
#define I2SR_IAL			BIT(4)
#define I2SR_IIF			BIT(1)
#define I2SR_RX_NO_AK			BIT(0)

static uint8_t i2c_io_read8(uint8_t bid, uint32_t address)
{
	return io_read8(i2c_bus[bid].va + address);
}

static void i2c_io_write8(uint8_t bid, uint32_t address, uint8_t data)
{
	return io_write8(i2c_bus[bid].va + address, data);
}

static bool bus_is_idle(uint32_t sr)
{
	return (sr & I2SR_IBB) == 0;
}

static bool bus_is_busy(uint32_t sr)
{
	return !bus_is_idle(sr);
}

static bool isr_active(uint32_t sr)
{
	return (sr & I2SR_IIF) == I2SR_IIF;
}

static struct ifdr_pair {
	uint32_t divider;
	uint8_t prescaler;
} ifdr_table[] = {
	{ 22,	0x20 }, { 24,	0x21 }, { 26,	0x22 }, { 28,	0x23 },
	{ 30,	0x00 }, { 32,	0x24 }, { 36,	0x25 }, { 40,	0x26 },
	{ 42,	0x03 }, { 44,	0x27 }, { 48,	0x28 }, { 52,	0x05 },
	{ 56,	0x29 }, { 60,	0x06 }, { 64,	0x2A }, { 72,	0x2B },
	{ 80,	0x2C }, { 88,	0x09 }, { 96,	0x2D }, { 104,	0x0A },
	{ 112,	0x2E }, { 128,	0x2F }, { 144,	0x0C }, { 160,	0x30 },
	{ 192,	0x31 }, { 224,	0x32 }, { 240,	0x0F }, { 256,	0x33 },
	{ 288,	0x10 }, { 320,	0x34 }, { 384,	0x35 }, { 448,	0x36 },
	{ 480,	0x13 }, { 512,	0x37 }, { 576,	0x14 }, { 640,	0x38 },
	{ 768,	0x39 }, { 896,	0x3A }, { 960,	0x17 }, { 1024,	0x3B },
	{ 1152,	0x18 }, { 1280,	0x3C }, { 1536,	0x3D }, { 1792,	0x3E },
	{ 1920,	0x1B }, { 2048,	0x3F }, { 2304,	0x1C }, { 2560,	0x1D },
	{ 3072,	0x1E }, { 3840,	0x1F }
};

static void i2c_set_prescaler(uint8_t bid, uint32_t bps)
{
	struct ifdr_pair *p = ifdr_table;
	struct ifdr_pair *q = p + ARRAY_SIZE(ifdr_table) - 1;
	uint32_t div = (I2C_CLK_RATE + bps - 1) / bps;

	if (div < p->divider)
		q = p;
	else if (div > q->divider)
		p = q;

	while (p != q) {
		if (div <= p->divider)
			break;
		p++;
	}

	i2c_io_write8(bid, IFDR, p->prescaler);
}

static void i2c_set_bus_speed(uint8_t bid, int bps)
{
	vaddr_t addr = i2c_clk.base.va;
	uint32_t val = 0;

#if defined(CFG_MX8MM) || defined(CFG_MX8MQ) || defined(CFG_MX8MP) || \
	defined(CFG_MX8MN)
	addr += CCM_CCGRx_SET(i2c_clk.i2c[bid]);
	val = CCM_CCGRx_ALWAYS_ON(0);
#elif defined(CFG_MX6ULL)
	addr += i2c_clk.i2c[bid];
	val = i2c_clk.cgrbm[bid] | io_read32(addr);
#else
#error IMX_I2C driver not supported on this platform
#endif
	io_write32(addr, val);
	i2c_set_prescaler(bid, bps);
}

static TEE_Result i2c_sync_bus(uint8_t bid, bool (*match)(uint32_t),
			       uint32_t *status)
{
	uint64_t tref = timeout_init_us(100000);
	uint32_t sr = 0;

	while (!timeout_elapsed(tref)) {
		sr = i2c_io_read8(bid, I2SR);
		if (sr & I2SR_IAL) {
			EMSG("bus arbitration lost");
			i2c_io_write8(bid, I2SR, sr & ~I2SR_IAL);
			return TEE_ERROR_COMMUNICATION;
		}
		if ((*match)(sr)) {
			if (status)
				*status = sr;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BUSY;
}

static TEE_Result i2c_idle_bus(uint8_t bid)
{
	uint8_t tmp = i2c_io_read8(bid, I2CR) & ~I2CR_MSTA;
	TEE_Result ret = TEE_SUCCESS;

	i2c_io_write8(bid, I2CR, tmp);
	ret = i2c_sync_bus(bid, &bus_is_idle, NULL);
	i2c_io_write8(bid, I2SR, 0);

	return ret;
}

static TEE_Result i2c_write_byte(uint8_t bid, uint8_t byte)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t status = 0;

	i2c_io_write8(bid, I2DR, byte);
	ret = i2c_sync_bus(bid, &isr_active, &status);
	i2c_io_write8(bid, I2SR, 0);

	if (!ret && (status & I2SR_RX_NO_AK))
		return TEE_ERROR_BAD_STATE;

	return ret;
}

static TEE_Result i2c_read_byte(uint8_t bid, uint8_t *p)
{
	TEE_Result ret = TEE_SUCCESS;

	*p = i2c_io_read8(bid, I2DR);
	ret = i2c_sync_bus(bid, &isr_active, NULL);
	i2c_io_write8(bid, I2SR, 0);

	return ret;
}

static TEE_Result i2c_write_data(uint8_t bid, const uint8_t *buf, int len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t tmp = 0;

	if (!len)
		return TEE_SUCCESS;

	tmp = i2c_io_read8(bid, I2CR) | I2CR_MTX | I2CR_TX_NO_AK;
	i2c_io_write8(bid, I2CR, tmp);

	while (len--) {
		ret = i2c_write_byte(bid, *buf++);
		if (ret)
			return ret;
	}

	return ret;
}

static TEE_Result i2c_read_data(uint8_t bid, uint8_t *buf, int len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint8_t dummy = 0;
	uint32_t tmp = 0;

	if (!len)
		return TEE_SUCCESS;

	tmp = i2c_io_read8(bid, I2CR) & ~I2CR_MTX;
	tmp = (len == 1) ? tmp | I2CR_TX_NO_AK : tmp & ~I2CR_TX_NO_AK;
	i2c_io_write8(bid, I2CR, tmp);
	i2c_io_read8(bid, I2DR);

	ret = i2c_read_byte(bid, &dummy);
	if (ret)
		return ret;

	/*
	 * A data transfer ends when the master signals a stop; for a master
	 * receiver to terminate a transfer it must inform the slave transmiter
	 * by not acknowledging the last data byte. This is done by setting the
	 * transmit acknowledge bit before reading the next-to-last byte.
	 */
	do {
		if (len == 2) {
			tmp = i2c_io_read8(bid, I2CR) | I2CR_TX_NO_AK;
			i2c_io_write8(bid, I2CR, tmp);
		}

		ret = i2c_read_byte(bid, buf++);
		if (ret)
			return ret;
	} while (len--);

	return ret;
}

static TEE_Result i2c_init_transfer(uint8_t bid, uint8_t chip)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t tmp = 0;

	ret = i2c_idle_bus(bid);
	if (ret)
		return ret;

	/* Enable the interface */
	tmp = !(i2c_io_read8(bid, I2CR) & I2CR_IEN);
	if (tmp) {
		i2c_io_write8(bid, I2CR, I2CR_IEN);
		udelay(50);
	}
	i2c_io_write8(bid, I2SR, 0);

	tmp = i2c_io_read8(bid, I2CR) | I2CR_MSTA;
	i2c_io_write8(bid, I2CR, tmp);

	/* Wait until the bus is active */
	ret = i2c_sync_bus(bid, &bus_is_busy, NULL);
	if (ret)
		return ret;

	/* Slave address on the bus */
	return i2c_write_data(bid, &chip, 1);
}

TEE_Result imx_i2c_read(uint8_t bid, uint8_t chip, uint8_t *buf, int len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (bid >= ARRAY_SIZE(i2c_bus))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((len && !buf) || chip > 0x7F)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!i2c_bus[bid].va)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = i2c_init_transfer(bid, chip << 1 | BIT(0));
	if (!ret)
		ret = i2c_read_data(bid, buf, len);

	if (i2c_idle_bus(bid))
		IMSG("bus not idle");

	return ret;
}

TEE_Result imx_i2c_write(uint8_t bid, uint8_t chip, const uint8_t *buf, int len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (bid >= ARRAY_SIZE(i2c_bus))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((len && !buf) || chip > 0x7F)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!i2c_bus[bid].va)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = i2c_init_transfer(bid, chip << 1);
	if (!ret)
		ret = i2c_write_data(bid, buf, len);

	if (i2c_idle_bus(bid))
		IMSG("bus not idle");

	return ret;
}

TEE_Result imx_i2c_probe(uint8_t bid, uint8_t chip)
{
	if (bid >= ARRAY_SIZE(i2c_bus))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!i2c_bus[bid].va)
		return TEE_ERROR_BAD_PARAMETERS;

	if (chip > 0x7F)
		return TEE_ERROR_BAD_PARAMETERS;

	return imx_i2c_write(bid, chip, NULL, 0);
}

/*
 * I2C bus initialization: configure the IOMUX and enable the clock.
 * @bid: Bus ID: (0=I2C1), (1=I2C2), (2=I2C3), (3=I2C4).
 * @bps: Bus baud rate, in bits per second.
 */
TEE_Result imx_i2c_init(uint8_t bid, int bps)
{
	struct imx_i2c_mux *mux = &i2c_mux;

	if (bid >= ARRAY_SIZE(i2c_bus))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!bps)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!i2c_bus[bid].va)
		return TEE_ERROR_BAD_PARAMETERS;

	io_write32(mux->base.va + mux->i2c[bid].scl_mux, I2C_MUX_VAL(bid));
	io_write32(mux->base.va + mux->i2c[bid].scl_cfg, I2C_CFG_VAL(bid));
	if (mux->i2c[bid].scl_inp)
		io_write32(mux->base.va + mux->i2c[bid].scl_inp,
			   I2C_INP_VAL(bid + 1));

	io_write32(mux->base.va + mux->i2c[bid].sda_mux, I2C_MUX_VAL(bid));
	io_write32(mux->base.va + mux->i2c[bid].sda_cfg, I2C_CFG_VAL(bid));
	if (mux->i2c[bid].sda_inp)
		io_write32(mux->base.va + mux->i2c[bid].sda_inp,
			   I2C_INP_VAL(bid + 2));

	/* Baud rate in bits per second */
	i2c_set_bus_speed(bid, bps);

	return TEE_SUCCESS;
}

static TEE_Result get_va(paddr_t pa, vaddr_t *va)
{
	*va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC, pa, 0x10000);
	if (!*va)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

#if defined(CFG_DT) && !defined(CFG_EXTERNAL_DTB_OVERLAY)
static const char *const dt_i2c_match_table[] = {
	"fsl,imx21-i2c",
};

static TEE_Result i2c_mapped(const char *i2c_match)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	void *fdt = get_dt();
	size_t size = 0;
	size_t i = 0;
	int off = 0;

	if (!fdt)
		return TEE_ERROR_NOT_SUPPORTED;

	for (i = 0; i < ARRAY_SIZE(i2c_bus); i++) {
		off = fdt_node_offset_by_compatible(fdt, off, i2c_match);
		if (off < 0)
			break;

		if (!(fdt_get_status(fdt, off) & DT_STATUS_OK_SEC)) {
			EMSG("i2c%zu not enabled", i + 1);
			continue;
		}

		if (dt_map_dev(fdt, off, &i2c_bus[i].va, &size,
			       DT_MAP_AUTO) < 0) {
			EMSG("i2c%zu not enabled", i + 1);
			continue;
		}

		i2c_bus[i].pa = virt_to_phys((void *)i2c_bus[i].va);
		ret = TEE_SUCCESS;
	}

	return ret;
}

static TEE_Result i2c_map_controller(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(dt_i2c_match_table); i++) {
		ret = i2c_mapped(dt_i2c_match_table[i]);
		if (!ret || ret == TEE_ERROR_NOT_SUPPORTED)
			return ret;
	}

	return ret;
}
#else
static TEE_Result i2c_map_controller(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(i2c_bus); n++) {
		if (i2c_bus[n].pa) {
			if (get_va(i2c_bus[n].pa, &i2c_bus[n].va))
				EMSG("i2c%zu not enabled", n + 1);
			else
				ret = TEE_SUCCESS;
		} else {
			IMSG("i2c%zu not enabled", n + 1);
		}
	}

	return ret;
}
#endif

static TEE_Result i2c_init(void)
{
	if (get_va(i2c_clk.base.pa, &i2c_clk.base.va))
		return TEE_ERROR_GENERIC;

	if (get_va(i2c_mux.base.pa, &i2c_mux.base.va))
		return TEE_ERROR_GENERIC;

	return i2c_map_controller();
}

early_init(i2c_init);
