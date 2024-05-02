// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2017, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2017-2024, STMicroelectronics
 */

/*
 * STM32 ETPZC acts as a firewall on stm32mp SoC peripheral interfaces and
 * internal memories. The driver expects a single instance of the controller
 * in the platform.
 */

#include <assert.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <util.h>

/* Devicetree compatibility */
#define ETZPC_LOCK_MASK			BIT(0)
#define ETZPC_MODE_SHIFT		8
#define ETZPC_MODE_MASK			GENMASK_32(1, 0)
#define ETZPC_ID_SHIFT			16
#define ETZPC_ID_MASK			GENMASK_32(7, 0)

/* ID Registers */
#define ETZPC_TZMA0_SIZE		U(0x000)
#define ETZPC_DECPROT0			U(0x010)
#define ETZPC_DECPROT_LOCK0		U(0x030)
#define ETZPC_HWCFGR			U(0x3F0)
#define ETZPC_VERR			U(0x3F4)

/* ID Registers fields */
#define ETZPC_TZMA0_SIZE_LOCK		BIT(31)
#define ETZPC_DECPROT0_MASK		GENMASK_32(1, 0)
#define ETZPC_HWCFGR_NUM_TZMA_MASK	GENMASK_32(7, 0)
#define ETZPC_HWCFGR_NUM_TZMA_SHIFT	0
#define ETZPC_HWCFGR_NUM_PER_SEC_MASK	GENMASK_32(15, 8)
#define ETZPC_HWCFGR_NUM_PER_SEC_SHIFT	8
#define ETZPC_HWCFGR_NUM_AHB_SEC_MASK	GENMASK_32(23, 16)
#define ETZPC_HWCFGR_NUM_AHB_SEC_SHIFT	16
#define ETZPC_HWCFGR_CHUNKS1N4_MASK	GENMASK_32(31, 24)
#define ETZPC_HWCFGR_CHUNKS1N4_SHIFT	24

#define DECPROT_SHIFT			1
#define IDS_PER_DECPROT_REGS		U(16)
#define IDS_PER_DECPROT_LOCK_REGS	U(32)

/*
 * Implementation uses uint8_t to store each securable DECPROT configuration
 * and uint16_t to store each securable TZMA configuration. When resuming
 * from deep suspend, the DECPROT configurations are restored.
 */
#define PERIPH_PM_LOCK_BIT		BIT(7)
#define PERIPH_PM_ATTR_MASK		GENMASK_32(2, 0)
#define TZMA_PM_LOCK_BIT		BIT(15)
#define TZMA_PM_VALUE_MASK		GENMASK_32(9, 0)

/*
 * struct stm32_etzpc_platdata - Driver data set at initialization
 *
 * @name:	Name of the peripheral
 * @clk:	ETZPC clock
 * @periph_cfg:	Peripheral DECPROT configuration
 * @tzma_cfg:	TZMA configuration
 * @base:	ETZPC IOMEM base address
 */
struct stm32_etzpc_platdata {
	const char *name;
	struct clk *clk;
	uint8_t *periph_cfg;
	uint16_t *tzma_cfg;
	struct io_pa_va base;
};

/*
 * struct stm32_etzpc_driver_data - configuration data from the hardware
 *
 * @num_tzma:	 Number of TZMA zones, read from the hardware
 * @num_per_sec: Number of securable AHB & APB periphs, read from the hardware
 * @num_ahb_sec: Number of securable AHB master zones, read from the hardware
 */
struct stm32_etzpc_driver_data {
	unsigned int num_tzma;
	unsigned int num_per_sec;
	unsigned int num_ahb_sec;
};

/*
 * struct etzpc_device - ETZPC device driver instance
 * @pdata:	Platform data set during initialization
 * @ddata:	Device configuration data from the hardware
 * @lock:	Access contention
 */
struct etzpc_device {
	struct stm32_etzpc_platdata pdata;
	struct stm32_etzpc_driver_data *ddata;
	unsigned int lock;
};

static struct etzpc_device *etzpc_device;

struct etzpc_device *stm32_get_etzpc_device(void)
{
	return etzpc_device;
}

static uint32_t etzpc_lock(struct etzpc_device *dev)
{
	return may_spin_lock(&dev->lock);
}

static void etzpc_unlock(struct etzpc_device *dev, uint32_t exceptions)
{
	may_spin_unlock(&dev->lock, exceptions);
}

static bool valid_decprot_id(struct etzpc_device *etzpc_dev, unsigned int id)
{
	return id < etzpc_dev->ddata->num_per_sec;
}

static bool __maybe_unused valid_tzma_id(struct etzpc_device *etzpc_dev,
					 unsigned int id)
{
	return id < etzpc_dev->ddata->num_tzma;
}

static enum etzpc_decprot_attributes etzpc_binding2decprot(uint32_t mode)
{
	switch (mode) {
	case DECPROT_S_RW:
		return ETZPC_DECPROT_S_RW;
	case DECPROT_NS_R_S_W:
		return ETZPC_DECPROT_NS_R_S_W;
#ifdef CFG_STM32MP15
	case DECPROT_MCU_ISOLATION:
		return ETZPC_DECPROT_MCU_ISOLATION;
#endif
	case DECPROT_NS_RW:
		return ETZPC_DECPROT_NS_RW;
	default:
		panic();
	}
}

static void etzpc_do_configure_decprot(struct etzpc_device *etzpc_dev,
				       uint32_t decprot_id,
				       enum etzpc_decprot_attributes attr)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_REGS);
	uint32_t shift = (decprot_id % IDS_PER_DECPROT_REGS) << DECPROT_SHIFT;
	uint32_t masked_decprot = (uint32_t)attr & ETZPC_DECPROT0_MASK;
	vaddr_t base = etzpc_dev->pdata.base.va;
	unsigned int exceptions = 0;

	assert(valid_decprot_id(etzpc_dev, decprot_id));

	FMSG("ID : %"PRIu32", CONF %d", decprot_id, attr);

	exceptions = etzpc_lock(etzpc_dev);

	io_clrsetbits32(base + ETZPC_DECPROT0 + offset,
			ETZPC_DECPROT0_MASK << shift,
			masked_decprot << shift);

	etzpc_unlock(etzpc_dev, exceptions);
}

static enum etzpc_decprot_attributes
etzpc_do_get_decprot(struct etzpc_device *etzpc_dev, uint32_t decprot_id)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_REGS);
	uint32_t shift = (decprot_id % IDS_PER_DECPROT_REGS) << DECPROT_SHIFT;
	vaddr_t base = etzpc_dev->pdata.base.va;
	uint32_t value = 0;

	assert(valid_decprot_id(etzpc_dev, decprot_id));

	value = (io_read32(base + ETZPC_DECPROT0 + offset) >> shift) &
		ETZPC_DECPROT0_MASK;

	return (enum etzpc_decprot_attributes)value;
}

static void etzpc_do_lock_decprot(struct etzpc_device *etzpc_dev,
				  uint32_t decprot_id)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_LOCK_REGS);
	uint32_t mask = BIT(decprot_id % IDS_PER_DECPROT_LOCK_REGS);
	vaddr_t base = etzpc_dev->pdata.base.va;
	uint32_t exceptions = 0;

	assert(valid_decprot_id(etzpc_dev, decprot_id));

	exceptions = etzpc_lock(etzpc_dev);

	io_write32(base + offset + ETZPC_DECPROT_LOCK0, mask);

	etzpc_unlock(etzpc_dev, exceptions);
}

static bool decprot_is_locked(struct etzpc_device *etzpc_dev,
			      uint32_t decprot_id)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_LOCK_REGS);
	uint32_t mask = BIT(decprot_id % IDS_PER_DECPROT_LOCK_REGS);
	vaddr_t base = etzpc_dev->pdata.base.va;

	assert(valid_decprot_id(etzpc_dev, decprot_id));

	return io_read32(base + offset + ETZPC_DECPROT_LOCK0) & mask;
}

void etzpc_do_configure_tzma(struct etzpc_device *etzpc_dev,
			     uint32_t tzma_id, uint16_t tzma_value)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_dev->pdata.base.va;
	uint32_t exceptions = 0;

	assert(valid_tzma_id(etzpc_dev, tzma_id));

	exceptions = etzpc_lock(etzpc_dev);

	io_write32(base + ETZPC_TZMA0_SIZE + offset, tzma_value);

	etzpc_unlock(etzpc_dev, exceptions);
}

static uint16_t etzpc_do_get_tzma(struct etzpc_device *etzpc_dev,
				  uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_dev->pdata.base.va;

	assert(valid_tzma_id(etzpc_dev, tzma_id));

	return io_read32(base + ETZPC_TZMA0_SIZE + offset);
}

static void etzpc_do_lock_tzma(struct etzpc_device *etzpc_dev, uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_dev->pdata.base.va;
	uint32_t exceptions = 0;

	assert(valid_tzma_id(etzpc_dev, tzma_id));

	exceptions = etzpc_lock(etzpc_dev);

	io_setbits32(base + ETZPC_TZMA0_SIZE + offset, ETZPC_TZMA0_SIZE_LOCK);

	etzpc_unlock(etzpc_dev, exceptions);
}

static bool tzma_is_locked(struct etzpc_device *etzpc_dev, uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_dev->pdata.base.va;

	assert(valid_tzma_id(etzpc_dev, tzma_id));

	return io_read32(base + ETZPC_TZMA0_SIZE + offset) &
	       ETZPC_TZMA0_SIZE_LOCK;
}

static TEE_Result etzpc_pm(enum pm_op op, unsigned int pm_hint __unused,
			   const struct pm_callback_handle *pm_handle)
{
	struct etzpc_device *etzpc_dev = (struct etzpc_device *)pm_handle;
	struct stm32_etzpc_driver_data *ddata = etzpc_dev->ddata;
	struct stm32_etzpc_platdata *pdata = &etzpc_dev->pdata;
	unsigned int n = 0;

	if (op == PM_OP_SUSPEND) {
		for (n = 0; n < ddata->num_per_sec; n++) {
			pdata->periph_cfg[n] =
				(uint8_t)etzpc_do_get_decprot(etzpc_dev, n);
			if (decprot_is_locked(etzpc_dev, n))
				pdata->periph_cfg[n] |= PERIPH_PM_LOCK_BIT;
		}

		for (n = 0; n < ddata->num_tzma; n++) {
			pdata->tzma_cfg[n] =
				(uint8_t)etzpc_do_get_tzma(etzpc_dev, n);
			if (tzma_is_locked(etzpc_dev, n))
				pdata->tzma_cfg[n] |= TZMA_PM_LOCK_BIT;
		}

		return TEE_SUCCESS;
	}

	/* PM_OP_RESUME */
	for (n = 0; n < ddata->num_per_sec; n++) {
		unsigned int attr = pdata->periph_cfg[n] & PERIPH_PM_ATTR_MASK;

		etzpc_do_configure_decprot(etzpc_dev, n,
					   (enum etzpc_decprot_attributes)attr);

		if (pdata->periph_cfg[n] & PERIPH_PM_LOCK_BIT)
			etzpc_do_lock_decprot(etzpc_dev, n);
	}

	for (n = 0; n < ddata->num_tzma; n++) {
		uint16_t value = pdata->tzma_cfg[n] & TZMA_PM_VALUE_MASK;

		etzpc_do_configure_tzma(etzpc_dev, n, value);

		if (pdata->tzma_cfg[n] & TZMA_PM_LOCK_BIT)
			etzpc_do_lock_tzma(etzpc_dev, n);
	}

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(etzpc_pm);

static struct etzpc_device *stm32_etzpc_alloc(void)
{
	struct etzpc_device *etzpc_dev = calloc(1, sizeof(*etzpc_dev));
	struct stm32_etzpc_driver_data *ddata = calloc(1, sizeof(*ddata));

	if (etzpc_dev && ddata) {
		etzpc_dev->ddata = ddata;
		return etzpc_dev;
	}

	free(ddata);
	free(etzpc_dev);

	return NULL;
}

/* Informative unused function */
static __unused void stm32_etzpc_free(struct etzpc_device *etzpc_dev)
{
	if (etzpc_dev) {
		free(etzpc_dev->ddata);
		free(etzpc_dev);
	}
}

static void stm32_etzpc_set_driverdata(struct etzpc_device *dev)
{
	struct stm32_etzpc_driver_data *ddata = dev->ddata;
	vaddr_t base = dev->pdata.base.va;
	uint32_t reg = io_read32(base + ETZPC_HWCFGR);

	ddata->num_tzma = (reg & ETZPC_HWCFGR_NUM_TZMA_MASK) >>
			  ETZPC_HWCFGR_NUM_TZMA_SHIFT;
	ddata->num_per_sec = (reg & ETZPC_HWCFGR_NUM_PER_SEC_MASK) >>
			     ETZPC_HWCFGR_NUM_PER_SEC_SHIFT;
	ddata->num_ahb_sec = (reg & ETZPC_HWCFGR_NUM_AHB_SEC_MASK) >>
			     ETZPC_HWCFGR_NUM_AHB_SEC_SHIFT;

	DMSG("ETZPC revision 0x%02"PRIx8", per_sec %u, ahb_sec %u, tzma %u",
	     io_read8(base + ETZPC_VERR),
	     ddata->num_per_sec, ddata->num_ahb_sec, ddata->num_tzma);
}

static void fdt_etzpc_conf_decprot(struct etzpc_device *dev,
				   const void *fdt, int node)
{
	const fdt32_t *cuint = NULL;
	size_t i = 0;
	int len = 0;

	cuint = fdt_getprop(fdt, node, "st,decprot", &len);
	if (!cuint) {
		DMSG("No ETZPC DECPROT configuration in DT");
		return;
	}

	clk_enable(dev->pdata.clk);

	for (i = 0; i < len / sizeof(uint32_t); i++) {
		uint32_t value = fdt32_to_cpu(cuint[i]);
		uint32_t id = (value >> ETZPC_ID_SHIFT) & ETZPC_ID_MASK;
		uint32_t mode = (value >> ETZPC_MODE_SHIFT) & ETZPC_MODE_MASK;
		bool lock = value & ETZPC_LOCK_MASK;
		enum etzpc_decprot_attributes attr = ETZPC_DECPROT_MAX;

		if (!valid_decprot_id(dev, id)) {
			DMSG("Invalid DECPROT %"PRIu32, id);
			panic();
		}

		attr = etzpc_binding2decprot(mode);
		etzpc_do_configure_decprot(dev, id, attr);

		if (lock)
			etzpc_do_lock_decprot(dev, id);
	}

	clk_disable(dev->pdata.clk);
}

static TEE_Result init_etzpc_from_dt(struct etzpc_device *etzpc_dev,
				     const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info etzpc_info = { };
	struct io_pa_va base = { };
	int len = 0;

	fdt_fill_device_info(fdt, &etzpc_info, node);
	if (etzpc_info.reg == DT_INFO_INVALID_REG ||
	    etzpc_info.reg_size == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	base.pa = etzpc_info.reg;
	etzpc_dev->pdata.name = fdt_get_name(fdt, node, &len);
	etzpc_dev->pdata.base.va = io_pa_or_va_secure(&base,
						      etzpc_info.reg_size);
	etzpc_dev->pdata.base = base;
	res = clk_dt_get_by_index(fdt, node, 0, &etzpc_dev->pdata.clk);
	if (res)
		return res;

	stm32_etzpc_set_driverdata(etzpc_dev);

	etzpc_dev->pdata.periph_cfg =
		calloc(etzpc_dev->ddata->num_per_sec,
		       sizeof(*etzpc_dev->pdata.periph_cfg));

	etzpc_dev->pdata.tzma_cfg =
		calloc(etzpc_dev->ddata->num_tzma,
		       sizeof(*etzpc_dev->pdata.tzma_cfg));
	if (!etzpc_dev->pdata.periph_cfg || !etzpc_dev->pdata.tzma_cfg)
		return TEE_ERROR_OUT_OF_MEMORY;

	fdt_etzpc_conf_decprot(etzpc_dev, fdt, node);

	return TEE_SUCCESS;
}

static TEE_Result stm32_etzpc_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct etzpc_device *etzpc_dev = stm32_etzpc_alloc();
	int subnode = 0;

	if (!etzpc_dev) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	res = init_etzpc_from_dt(etzpc_dev, fdt, node);
	if (res) {
		free(etzpc_dev->pdata.tzma_cfg);
		free(etzpc_dev);
		return res;
	}

	etzpc_device = etzpc_dev;

	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed to add node %s to probe list: %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	register_pm_core_service_cb(etzpc_pm, etzpc_dev, "stm32-etzpc");

	return TEE_SUCCESS;

err:
	EMSG("ETZPC probe failed: %#"PRIx32, res);
	panic();
}

static const struct dt_device_match etzpc_match_table[] = {
	{ .compatible = "st,stm32-etzpc", },
	{ }
};

DEFINE_DT_DRIVER(etzpc_dt_driver) = {
	.name = "stm32-etzpc",
	.match_table = etzpc_match_table,
	.probe = stm32_etzpc_probe,
};
