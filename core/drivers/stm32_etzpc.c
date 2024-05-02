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
	char *name;
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
	struct stm32_etzpc_driver_data ddata;
	unsigned int lock;
};

static struct etzpc_device *etzpc_device;

static uint32_t etzpc_lock(void)
{
	return cpu_spin_lock_xsave(&etzpc_device->lock);
}

static void etzpc_unlock(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&etzpc_device->lock, exceptions);
}

static bool valid_decprot_id(unsigned int id)
{
	return id < etzpc_device->ddata.num_per_sec;
}

static bool __maybe_unused valid_tzma_id(unsigned int id)
{
	return id < etzpc_device->ddata.num_tzma;
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

static void etzpc_configure_decprot(uint32_t decprot_id,
				    enum etzpc_decprot_attributes attr)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_REGS);
	uint32_t shift = (decprot_id % IDS_PER_DECPROT_REGS) << DECPROT_SHIFT;
	uint32_t masked_decprot = (uint32_t)attr & ETZPC_DECPROT0_MASK;
	vaddr_t base = etzpc_device->pdata.base.va;
	unsigned int exceptions = 0;

	assert(valid_decprot_id(decprot_id));

	DMSG("ID : %"PRIu32", CONF %d", decprot_id, attr);

	exceptions = etzpc_lock();

	io_clrsetbits32(base + ETZPC_DECPROT0 + offset,
			ETZPC_DECPROT0_MASK << shift,
			masked_decprot << shift);

	etzpc_unlock(exceptions);
}

enum etzpc_decprot_attributes etzpc_get_decprot(uint32_t decprot_id)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_REGS);
	uint32_t shift = (decprot_id % IDS_PER_DECPROT_REGS) << DECPROT_SHIFT;
	vaddr_t base = etzpc_device->pdata.base.va;
	uint32_t value = 0;

	assert(valid_decprot_id(decprot_id));

	value = (io_read32(base + ETZPC_DECPROT0 + offset) >> shift) &
		ETZPC_DECPROT0_MASK;

	return (enum etzpc_decprot_attributes)value;
}

static void etzpc_lock_decprot(uint32_t decprot_id)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_LOCK_REGS);
	uint32_t mask = BIT(decprot_id % IDS_PER_DECPROT_LOCK_REGS);
	vaddr_t base = etzpc_device->pdata.base.va;
	uint32_t exceptions = 0;

	assert(valid_decprot_id(decprot_id));

	exceptions = etzpc_lock();

	io_write32(base + offset + ETZPC_DECPROT_LOCK0, mask);

	etzpc_unlock(exceptions);
}

static bool decprot_is_locked(uint32_t decprot_id)
{
	size_t offset = U(4) * (decprot_id / IDS_PER_DECPROT_LOCK_REGS);
	uint32_t mask = BIT(decprot_id % IDS_PER_DECPROT_LOCK_REGS);
	vaddr_t base = etzpc_device->pdata.base.va;

	assert(valid_decprot_id(decprot_id));

	return io_read32(base + offset + ETZPC_DECPROT_LOCK0) & mask;
}

void etzpc_configure_tzma(uint32_t tzma_id, uint16_t tzma_value)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_device->pdata.base.va;
	uint32_t exceptions = 0;

	assert(valid_tzma_id(tzma_id));

	exceptions = etzpc_lock();

	io_write32(base + ETZPC_TZMA0_SIZE + offset, tzma_value);

	etzpc_unlock(exceptions);
}

static uint16_t etzpc_get_tzma(uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_device->pdata.base.va;

	assert(valid_tzma_id(tzma_id));

	return io_read32(base + ETZPC_TZMA0_SIZE + offset);
}

static void etzpc_lock_tzma(uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_device->pdata.base.va;
	uint32_t exceptions = 0;

	assert(valid_tzma_id(tzma_id));

	exceptions = etzpc_lock();

	io_setbits32(base + ETZPC_TZMA0_SIZE + offset, ETZPC_TZMA0_SIZE_LOCK);

	etzpc_unlock(exceptions);
}

static bool tzma_is_locked(uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_device->pdata.base.va;

	assert(valid_tzma_id(tzma_id));

	return io_read32(base + ETZPC_TZMA0_SIZE + offset) &
	       ETZPC_TZMA0_SIZE_LOCK;
}

static TEE_Result etzpc_pm(enum pm_op op, unsigned int pm_hint __unused,
			   const struct pm_callback_handle *pm_handle __unused)
{
	struct stm32_etzpc_driver_data *ddata = &etzpc_device->ddata;
	struct stm32_etzpc_platdata *pdata = &etzpc_device->pdata;
	unsigned int n = 0;

	if (op == PM_OP_SUSPEND) {
		for (n = 0; n < ddata->num_per_sec; n++) {
			pdata->periph_cfg[n] =
				(uint8_t)etzpc_get_decprot(n);
			if (decprot_is_locked(n))
				pdata->periph_cfg[n] |= PERIPH_PM_LOCK_BIT;
		}

		for (n = 0; n < ddata->num_tzma; n++) {
			pdata->tzma_cfg[n] =
				(uint8_t)etzpc_get_tzma(n);
			if (tzma_is_locked(n))
				pdata->tzma_cfg[n] |= TZMA_PM_LOCK_BIT;
		}

		return TEE_SUCCESS;
	}

	/* PM_OP_RESUME */
	for (n = 0; n < ddata->num_per_sec; n++) {
		unsigned int attr = pdata->periph_cfg[n] & PERIPH_PM_ATTR_MASK;

		etzpc_configure_decprot(n, (enum etzpc_decprot_attributes)attr);

		if (pdata->periph_cfg[n] & PERIPH_PM_LOCK_BIT)
			etzpc_lock_decprot(n);
	}

	for (n = 0; n < ddata->num_tzma; n++) {
		uint16_t value = pdata->tzma_cfg[n] & TZMA_PM_VALUE_MASK;

		etzpc_configure_tzma(n, value);

		if (pdata->tzma_cfg[n] & TZMA_PM_LOCK_BIT)
			etzpc_lock_tzma(n);
	}

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(etzpc_pm);

static void stm32_etzpc_set_driverdata(void)
{
	struct stm32_etzpc_driver_data *ddata = &etzpc_device->ddata;
	vaddr_t base = etzpc_device->pdata.base.va;
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

static void fdt_etzpc_conf_decprot(const void *fdt, int node)
{
	const fdt32_t *cuint = NULL;
	size_t i = 0;
	int len = 0;

	cuint = fdt_getprop(fdt, node, "st,decprot", &len);
	if (!cuint) {
		DMSG("No ETZPC DECPROT configuration in DT");
		return;
	}

	clk_enable(etzpc_device->pdata.clk);

	for (i = 0; i < len / sizeof(uint32_t); i++) {
		uint32_t value = fdt32_to_cpu(cuint[i]);
		uint32_t id = value & ETZPC_ID_MASK;
		uint32_t mode = (value & ETZPC_MODE_MASK) >> ETZPC_MODE_SHIFT;
		bool lock = value & ETZPC_LOCK_MASK;
		enum etzpc_decprot_attributes attr = ETZPC_DECPROT_MAX;

		if (!valid_decprot_id(id)) {
			DMSG("Invalid DECPROT %"PRIu32, id);
			panic();
		}

		attr = etzpc_binding2decprot(mode);
		etzpc_configure_decprot(id, attr);

		if (lock)
			etzpc_lock_decprot(id);
	}

	clk_disable(etzpc_device->pdata.clk);
}

static TEE_Result init_etzpc_from_dt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info etzpc_info = { };
	int len = 0;

	fdt_fill_device_info(fdt, &etzpc_info, node);
	if (etzpc_info.reg == DT_INFO_INVALID_REG ||
	    etzpc_info.reg_size == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	etzpc_device->pdata.base.pa = etzpc_info.reg;
	etzpc_device->pdata.name = strdup(fdt_get_name(fdt, node, &len));
	io_pa_or_va_secure(&etzpc_device->pdata.base, etzpc_info.reg_size);
	res = clk_dt_get_by_index(fdt, node, 0, &etzpc_device->pdata.clk);
	if (res)
		return res;

	stm32_etzpc_set_driverdata();

	etzpc_device->pdata.periph_cfg =
		calloc(etzpc_device->ddata.num_per_sec,
		       sizeof(*etzpc_device->pdata.periph_cfg));

	etzpc_device->pdata.tzma_cfg =
		calloc(etzpc_device->ddata.num_tzma,
		       sizeof(*etzpc_device->pdata.tzma_cfg));
	if (!etzpc_device->pdata.periph_cfg || !etzpc_device->pdata.tzma_cfg)
		return TEE_ERROR_OUT_OF_MEMORY;

	fdt_etzpc_conf_decprot(fdt, node);

	return TEE_SUCCESS;
}

static TEE_Result stm32_etzpc_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int subnode = 0;

	etzpc_device = calloc(1, sizeof(*etzpc_device));
	if (!etzpc_device)
		panic("ETZPC probe failed");

	res = init_etzpc_from_dt(fdt, node);
	if (res) {
		free(etzpc_device->pdata.periph_cfg);
		free(etzpc_device->pdata.tzma_cfg);
		free(etzpc_device->pdata.name);
		free(etzpc_device);
		return res;
	}

	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed to add node %s to probe list: %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	register_pm_core_service_cb(etzpc_pm, NULL, "stm32-etzpc");

	return TEE_SUCCESS;
}

static const struct dt_device_match etzpc_match_table[] = {
	{ .compatible = "st,stm32-etzpc" },
	{ }
};

DEFINE_DT_DRIVER(etzpc_dt_driver) = {
	.name = "stm32-etzpc",
	.match_table = etzpc_match_table,
	.probe = stm32_etzpc_probe,
};
