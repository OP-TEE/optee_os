// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2017, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2017-2019, STMicroelectronics
 */

/*
 * STM32 ETPZC acts as a firewall on stm32mp SoC peripheral interfaces and
 * internal memories. The driver expects a single instance of the controller
 * in the platform.
 *
 * The driver API is defined in header file stm32_etzpc.h.
 *
 * Driver registers a PM callback for restoration of the access permissions
 * when it resumes.
 */

#include <assert.h>
#include <drivers/stm32_etzpc.h>
#include <kernel/dt.h>
#include <kernel/generic_boot.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <mm/core_memprot.h>
#include <util.h>

#ifdef CFG_DT
#include <libfdt.h>
#endif

/* Devicetree compatibulity */
#define ETZPC_COMPAT			"st,stm32-etzpc"

/* ID Registers */
#define ETZPC_TZMA0_SIZE		0x000U
#define ETZPC_DECPROT0			0x010U
#define ETZPC_DECPROT_LOCK0		0x030U
#define ETZPC_HWCFGR			0x3F0U
#define ETZPC_VERR			0x3F4U

/* ID Registers fields */
#define ETZPC_TZMA0_SIZE_LOCK		BIT(31)
#define ETZPC_DECPROT0_MASK		GENMASK_32(1, 0)
#define ETZPC_HWCFGR_NUM_TZMA_MASK	GENMASK_32(7, 0)
#define ETZPC_HWCFGR_NUM_TZMA_SHIFT	0
#define ETZPC_HWCFGR_NUM_PER_SEC_MASK	GENMASK_32(15, 8)
#define ETZPC_HWCFGR_NUM_PER_SEC_SHIFT	8
#define ETZPC_HWCFGR_NUM_AHB_SEC_MASK	GENMASK_32(23, 16)
#define ETZPC_HWCFGR_NUM_AHB_SEC_SHIFT	16
#define ETZPC_HWCFGR_CHUNCKS1N4_MASK	GENMASK_32(31, 24)
#define ETZPC_HWCFGR_CHUNCKS1N4_SHIFT	24

#define DECPROT_SHIFT			1
#define IDS_PER_DECPROT_REGS		16U
#define IDS_PER_DECPROT_LOCK_REGS	32U

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
 * @base - iobase for interface base address
 * @num_tzma - number of TZMA zone, read from the hardware
 * @num_ahb_sec - number of securable AHB master zone, read from the hardware
 * @num_per_sec - number of securable AHB & APB periphs, read from the hardware
 * @periph_cfg - Backup for restoring DECPROT when resuming (PERIH_PM_*)
 * @tzma_cfg - Backup for restoring TZMA when resuming (TZMA_PM_*)
 */
struct etzpc_instance {
	struct io_pa_va base;
	unsigned int num_tzma;
	unsigned int num_per_sec;
	unsigned int num_ahb_sec;
	uint8_t *periph_cfg;
	uint16_t *tzma_cfg;
};

/* Only 1 instance of the ETZPC is expected per platform */
static struct etzpc_instance etzpc_dev;

static vaddr_t etzpc_base(void)
{
	return io_pa_or_va(&etzpc_dev.base);
}

static bool valid_decprot_id(unsigned int id)
{
	return id < etzpc_dev.num_per_sec;
}

static bool valid_tzma_id(unsigned int id)
{
	return id < etzpc_dev.num_tzma;
}

void etzpc_configure_decprot(uint32_t decprot_id,
			     enum etzpc_decprot_attributes decprot_attr)
{
	size_t offset = 4U * (decprot_id / IDS_PER_DECPROT_REGS);
	uint32_t shift = (decprot_id % IDS_PER_DECPROT_REGS) << DECPROT_SHIFT;
	uint32_t masked_decprot = (uint32_t)decprot_attr & ETZPC_DECPROT0_MASK;
	vaddr_t base = etzpc_base();

	assert(valid_decprot_id(decprot_id));

	io_clrsetbits32(base + ETZPC_DECPROT0 + offset,
			ETZPC_DECPROT0_MASK << shift,
			masked_decprot << shift);

	/* Save for PM */
	assert((decprot_attr & ~PERIPH_PM_ATTR_MASK) == 0);
	COMPILE_TIME_ASSERT(ETZPC_DECPROT_MAX <= UINT8_MAX);

	etzpc_dev.periph_cfg[decprot_id] &= ~PERIPH_PM_ATTR_MASK;
	etzpc_dev.periph_cfg[decprot_id] |= (uint8_t)decprot_attr;
}

enum etzpc_decprot_attributes etzpc_get_decprot(uint32_t decprot_id)
{
	size_t offset = 4U * (decprot_id / IDS_PER_DECPROT_REGS);
	uint32_t shift = (decprot_id % IDS_PER_DECPROT_REGS) << DECPROT_SHIFT;
	vaddr_t base = etzpc_base();
	uint32_t value;

	assert(valid_decprot_id(decprot_id));

	value = (io_read32(base + ETZPC_DECPROT0 + offset) >> shift) &
		ETZPC_DECPROT0_MASK;

	return (enum etzpc_decprot_attributes)value;
}

void etzpc_lock_decprot(uint32_t decprot_id)
{
	size_t offset = 4U * (decprot_id / IDS_PER_DECPROT_LOCK_REGS);
	uint32_t mask = BIT(decprot_id % IDS_PER_DECPROT_LOCK_REGS);
	vaddr_t base = etzpc_base();

	assert(valid_decprot_id(decprot_id));

	io_write32(base + offset + ETZPC_DECPROT_LOCK0, mask);

	/* Save for PM */
	etzpc_dev.periph_cfg[decprot_id] |= PERIPH_PM_LOCK_BIT;
}

bool etzpc_get_lock_decprot(uint32_t decprot_id)
{
	size_t offset = 4U * (decprot_id / IDS_PER_DECPROT_LOCK_REGS);
	uint32_t mask = BIT(decprot_id % IDS_PER_DECPROT_LOCK_REGS);
	vaddr_t base = etzpc_base();

	assert(valid_decprot_id(decprot_id));

	return io_read32(base + offset + ETZPC_DECPROT_LOCK0) & mask;
}

void etzpc_configure_tzma(uint32_t tzma_id, uint16_t tzma_value)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_base();

	assert(valid_tzma_id(tzma_id));

	io_write32(base + ETZPC_TZMA0_SIZE + offset, tzma_value);

	/* Save for PM */
	assert((tzma_value & ~TZMA_PM_VALUE_MASK) == 0);
	etzpc_dev.tzma_cfg[tzma_id] &= ~TZMA_PM_VALUE_MASK;
	etzpc_dev.tzma_cfg[tzma_id] |= tzma_value;
}

uint16_t etzpc_get_tzma(uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_base();

	assert(valid_tzma_id(tzma_id));

	return io_read32(base + ETZPC_TZMA0_SIZE + offset);
}

void etzpc_lock_tzma(uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_base();

	assert(valid_tzma_id(tzma_id));

	io_setbits32(base + ETZPC_TZMA0_SIZE + offset, ETZPC_TZMA0_SIZE_LOCK);

	/* Save for PM */
	etzpc_dev.tzma_cfg[tzma_id] |= TZMA_PM_LOCK_BIT;
}

bool etzpc_get_lock_tzma(uint32_t tzma_id)
{
	size_t offset = sizeof(uint32_t) * tzma_id;
	vaddr_t base = etzpc_base();

	assert(valid_tzma_id(tzma_id));

	return io_read32(base + ETZPC_TZMA0_SIZE + offset) &
	       ETZPC_TZMA0_SIZE_LOCK;
}

static TEE_Result etzpc_pm(enum pm_op op, unsigned int pm_hint __unused,
			  const struct pm_callback_handle *pm_handle)
{
	struct etzpc_instance *dev;
	unsigned int n;

	if (op != PM_OP_RESUME)
		return TEE_SUCCESS;

	dev = (struct etzpc_instance *)PM_CALLBACK_GET_HANDLE(pm_handle);

	for (n = 0; n < dev->num_per_sec; n++) {
		unsigned int attr = dev->periph_cfg[n] & PERIPH_PM_ATTR_MASK;

		etzpc_configure_decprot(n, (enum etzpc_decprot_attributes)attr);

		if (dev->periph_cfg[n] & PERIPH_PM_LOCK_BIT)
			etzpc_lock_decprot(n);
	}

	for (n = 0; n < dev->num_tzma; n++) {
		uint16_t value = dev->tzma_cfg[n] & TZMA_PM_VALUE_MASK;

		etzpc_configure_tzma(n, value);

		if (dev->tzma_cfg[n] & TZMA_PM_LOCK_BIT)
			etzpc_lock_tzma(n);
	}

	return TEE_SUCCESS;
}
KEEP_PAGER(etzpc_pm);

static void init_pm(struct etzpc_instance *dev)
{
	unsigned int n;

	dev->periph_cfg = calloc(dev->num_per_sec, sizeof(*dev->periph_cfg));
	dev->tzma_cfg = calloc(dev->num_tzma, sizeof(*dev->tzma_cfg));
	if (!dev->periph_cfg || !dev->tzma_cfg)
		panic();

	for (n = 0; n < dev->num_per_sec; n++) {
		dev->periph_cfg[n] = (uint8_t)etzpc_get_decprot(n);
		if (etzpc_get_lock_decprot(n))
			dev->periph_cfg[n] |= PERIPH_PM_LOCK_BIT;
	}

	for (n = 0; n < dev->num_ahb_sec; n++) {
		dev->tzma_cfg[n] = (uint8_t)etzpc_get_tzma(n);
		if (etzpc_get_lock_tzma(n))
			dev->tzma_cfg[n] |= TZMA_PM_LOCK_BIT;
	}

	register_pm_driver_cb(etzpc_pm, dev);
}

struct etzpc_hwcfg {
	unsigned int num_tzma;
	unsigned int num_per_sec;
	unsigned int num_ahb_sec;
	unsigned int chunk_size;
};

static void get_hwcfg(struct etzpc_hwcfg *hwcfg)
{
	uint32_t reg = io_read32(etzpc_base() + ETZPC_HWCFGR);

	hwcfg->num_tzma = (reg & ETZPC_HWCFGR_NUM_TZMA_MASK) >>
			  ETZPC_HWCFGR_NUM_TZMA_SHIFT;
	hwcfg->num_per_sec = (reg & ETZPC_HWCFGR_NUM_PER_SEC_MASK) >>
			     ETZPC_HWCFGR_NUM_PER_SEC_SHIFT;
	hwcfg->num_ahb_sec = (reg & ETZPC_HWCFGR_NUM_AHB_SEC_MASK) >>
			     ETZPC_HWCFGR_NUM_AHB_SEC_SHIFT;
	hwcfg->chunk_size = (reg & ETZPC_HWCFGR_CHUNCKS1N4_MASK) >>
			    ETZPC_HWCFGR_CHUNCKS1N4_SHIFT;
}

static void init_devive_from_hw_config(struct etzpc_instance *dev,
					      paddr_t pbase)
{
	struct etzpc_hwcfg hwcfg;

	assert(!dev->base.pa && cpu_mmu_enabled());
	dev->base.pa = pbase;
	dev->base.va = (vaddr_t)phys_to_virt(dev->base.pa, MEM_AREA_IO_SEC);
	assert(etzpc_base());

	get_hwcfg(&hwcfg);
	dev->num_tzma = hwcfg.num_tzma;
	dev->num_per_sec = hwcfg.num_per_sec;
	dev->num_ahb_sec = hwcfg.num_ahb_sec;

	DMSG("ETZPC revison 0x02%" PRIu8 ", per_sec %u, ahb_sec %u, tzma %u",
	     io_read8(etzpc_base() + ETZPC_VERR),
	     hwcfg.num_per_sec, hwcfg.num_ahb_sec, hwcfg.num_tzma);

	init_pm(dev);
}

void stm32_etzpc_init(paddr_t base)
{
	init_devive_from_hw_config(&etzpc_dev, base);
}

#ifdef CFG_DT
static TEE_Result init_etzpc_from_dt(void)
{
	void *fdt = get_embedded_dt();
	int node = fdt_node_offset_by_compatible(fdt, -1, ETZPC_COMPAT);
	int status;
	paddr_t pbase;

	/* When using DT, expect one and only one instance, secure enabled */

	if (node < 0)
		panic();
	assert(fdt_node_offset_by_compatible(fdt, node, ETZPC_COMPAT) < 0);

	status = _fdt_get_status(fdt, node);
	if (!(status & DT_STATUS_OK_SEC))
		panic();

	pbase = _fdt_reg_base_address(fdt, node);
	if (pbase == (paddr_t)-1)
		panic();

	init_devive_from_hw_config(&etzpc_dev, pbase);

	return TEE_SUCCESS;
}

driver_init(init_etzpc_from_dt);
#endif /*CFG_DT*/
