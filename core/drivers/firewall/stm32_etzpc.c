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
#include <drivers/firewall.h>
#include <drivers/firewall_device.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32mp_dt_bindings.h>
#ifdef CFG_STM32MP15
#include <drivers/stm32mp1_rcc.h>
#endif
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
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

static const char *const etzpc_decprot_strings[] __maybe_unused = {
	[ETZPC_DECPROT_S_RW] = "ETZPC_DECPROT_S_RW",
	[ETZPC_DECPROT_NS_R_S_W] = "ETZPC_DECPROT_NS_R_S_W",
	[ETZPC_DECPROT_MCU_ISOLATION] = "ETZPC_DECPROT_MCU_ISOLATION",
	[ETZPC_DECPROT_NS_RW] = "ETZPC_DECPROT_NS_RW",
};

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

static void
sanitize_decprot_config(uint32_t decprot_id __maybe_unused,
			enum etzpc_decprot_attributes attr __maybe_unused)
{
#ifdef CFG_STM32MP15
	/*
	 * STM32MP15: check dependency on RCC TZEN/MCKPROT configuration
	 * when a ETZPC resource is secured or isolated for Cortex-M
	 * coprocessor.
	 */
	switch (attr) {
	case ETZPC_DECPROT_S_RW:
	case ETZPC_DECPROT_NS_R_S_W:
		if (!stm32_rcc_is_secure()) {
			IMSG("WARNING: RCC tzen:0, insecure ETZPC hardening %"PRIu32":%s",
			     decprot_id, etzpc_decprot_strings[attr]);
			if (!IS_ENABLED(CFG_INSECURE))
				panic();
		}
		break;
	case ETZPC_DECPROT_MCU_ISOLATION:
		if (!stm32_rcc_is_secure() || !stm32_rcc_is_mckprot()) {
			IMSG("WARNING: RCC tzen:%u mckprot:%u, insecure ETZPC hardening %"PRIu32":%s",
			     stm32_rcc_is_secure(), stm32_rcc_is_mckprot(),
			     decprot_id, etzpc_decprot_strings[attr]);
			if (!IS_ENABLED(CFG_INSECURE))
				panic();
		}
		break;
	case ETZPC_DECPROT_NS_RW:
		break;
	default:
		assert(0);
		break;
	}
#endif
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

	FMSG("ID : %"PRIu32", config %i", decprot_id, attr);

	sanitize_decprot_config(decprot_id, attr);

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

static TEE_Result stm32_etzpc_check_access(struct firewall_query *firewall)
{
	enum etzpc_decprot_attributes attr_req = ETZPC_DECPROT_MAX;
	uint32_t id = 0;

	if (!firewall || firewall->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	id = firewall->args[0] & ETZPC_ID_MASK;
	attr_req = etzpc_binding2decprot((firewall->args[0] &
					  ETZPC_MODE_MASK) >> ETZPC_MODE_SHIFT);

	if (id < etzpc_device->ddata.num_per_sec) {
		if (etzpc_get_decprot(id) == attr_req)
			return TEE_SUCCESS;
		else
			return TEE_ERROR_ACCESS_DENIED;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result stm32_etzpc_acquire_access(struct firewall_query *firewall)
{
	enum etzpc_decprot_attributes attr = ETZPC_DECPROT_MCU_ISOLATION;
	uint32_t id = 0;

	if (!firewall || firewall->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	id = firewall->args[0] & ETZPC_ID_MASK;
	if (id < etzpc_device->ddata.num_per_sec) {
		attr = etzpc_get_decprot(id);
		if (attr != ETZPC_DECPROT_S_RW &&
		    attr != ETZPC_DECPROT_NS_R_S_W)
			return TEE_ERROR_ACCESS_DENIED;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32_etzpc_acquire_memory_access(struct firewall_query *firewall,
				  paddr_t paddr, size_t size,
				  bool read __unused, bool write __unused)
{
	paddr_t tzma_base = 0;
	size_t prot_size = 0;
	uint32_t id = 0;

	if (!firewall || firewall->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	id = firewall->args[0] & ETZPC_ID_MASK;
	switch (id) {
	case ETZPC_TZMA0_ID:
		tzma_base = ROM_BASE;
		prot_size = etzpc_get_tzma(0) * SMALL_PAGE_SIZE;
		break;
	case ETZPC_TZMA1_ID:
		tzma_base = SYSRAM_BASE;
		prot_size = etzpc_get_tzma(1) * SMALL_PAGE_SIZE;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	DMSG("Acquiring access for TZMA%u, secured from %#"PRIxPA" to %#"PRIxPA,
	     id == ETZPC_TZMA0_ID ? 0 : 1, tzma_base, tzma_base + prot_size);

	if (core_is_buffer_inside(paddr, size, tzma_base, prot_size))
		return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_DENIED;
}

#ifdef CFG_STM32MP15
static bool pager_permits_decprot_config(uint32_t decprot_id,
					 enum etzpc_decprot_attributes attr)
{
	paddr_t ram_base = 0;
	size_t ram_size = 0;

	if (!IS_ENABLED(CFG_WITH_PAGER))
		return true;

	switch (decprot_id) {
	case ETZPC_TZMA1_ID:
		ram_base = SYSRAM_BASE;
		ram_size = SYSRAM_SEC_SIZE;
		break;
	case STM32MP1_ETZPC_SRAM1_ID:
		ram_base = SRAM1_BASE;
		ram_size = SRAM1_SIZE;
		break;
	case STM32MP1_ETZPC_SRAM2_ID:
		ram_base = SRAM2_BASE;
		ram_size = SRAM2_SIZE;
		break;
	case STM32MP1_ETZPC_SRAM3_ID:
		ram_base = SRAM3_BASE;
		ram_size = SRAM3_SIZE;
		break;
	case STM32MP1_ETZPC_SRAM4_ID:
		ram_base = SRAM4_BASE;
		ram_size = SRAM4_SIZE;
		break;
	default:
		return true;
	}

	if (stm32mp1_ram_intersect_pager_ram(ram_base, ram_size) &&
	    attr != ETZPC_DECPROT_S_RW) {
		EMSG("Internal RAM %#"PRIxPA"..%#"PRIxPA" is used by pager, must be secure",
		     ram_base, ram_base + ram_size);
		return false;
	}

	return true;
}
#endif /* CFG_STM32MP15 */

static bool decprot_id_is_internal_ram(uint32_t id)
{
	switch (id) {
	case STM32MP1_ETZPC_SRAM1_ID:
	case STM32MP1_ETZPC_SRAM2_ID:
	case STM32MP1_ETZPC_SRAM3_ID:
#ifdef CFG_STM32MP15
	case STM32MP1_ETZPC_SRAM4_ID:
	case STM32MP1_ETZPC_RETRAM_ID:
#endif
		return true;
	default:
		return false;
	}
}

static TEE_Result stm32_etzpc_configure_memory(struct firewall_query *firewall,
					       paddr_t paddr, size_t size)
{
	enum etzpc_decprot_attributes attr = ETZPC_DECPROT_MAX;
	bool lock = false;
	uint32_t mode = 0;
	uint32_t id = 0;

	if (firewall->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	id = firewall->args[0] & ETZPC_ID_MASK;
	mode = (firewall->args[0] & ETZPC_MODE_MASK) >> ETZPC_MODE_SHIFT;
	attr = etzpc_binding2decprot(mode);
	lock = firewall->args[0] & ETZPC_LOCK_MASK;

	if (decprot_id_is_internal_ram(id)) {
		/* Use OP-TEE SRAM addresses, not the alias one */
		paddr = stm32mp1_pa_or_sram_alias_pa(paddr);

		/* Target address range must match the full SRAM range */
		switch (id) {
		case STM32MP1_ETZPC_SRAM1_ID:
			if (paddr != SRAM1_BASE || size != SRAM1_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			break;
		case STM32MP1_ETZPC_SRAM2_ID:
			if (paddr != SRAM2_BASE || size != SRAM2_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			break;
		case STM32MP1_ETZPC_SRAM3_ID:
			if (paddr != SRAM3_BASE || size != SRAM3_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			break;
#ifdef CFG_STM32MP15
		case STM32MP1_ETZPC_SRAM4_ID:
			if (paddr != SRAM4_BASE || size != SRAM4_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			break;
		case STM32MP1_ETZPC_RETRAM_ID:
			if (paddr != RETRAM_BASE || size != RETRAM_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			break;
#endif /*CFG_STM32MP15*/
		default:
			panic();
		}

		if (decprot_is_locked(id)) {
			if (etzpc_get_decprot(id) != attr) {
				EMSG("Internal RAM configuration locked");
				return TEE_ERROR_ACCESS_DENIED;
			}

			return TEE_SUCCESS;
		}

#ifdef CFG_STM32MP15
		if (!pager_permits_decprot_config(id, attr))
			return TEE_ERROR_ACCESS_DENIED;
#endif

		etzpc_configure_decprot(id, attr);
		if (lock)
			etzpc_lock_decprot(id);
	} else if (id == ETZPC_TZMA0_ID || id == ETZPC_TZMA1_ID) {
		unsigned int tzma_id = 0;
		uint16_t tzma_r0size = 0;
		paddr_t ram_base = 0;
		size_t ram_size = 0;

		switch (id) {
		case ETZPC_TZMA0_ID:
			ram_base = ROM_BASE;
			ram_size = ROM_SIZE;
			tzma_id = 0;
			break;
		case ETZPC_TZMA1_ID:
			ram_base = SYSRAM_BASE;
			ram_size = SYSRAM_SIZE;
			tzma_id = 1;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}

		/* TZMA configuration supports only page aligned sizes */
		if (!IS_ALIGNED(paddr, SMALL_PAGE_SIZE) ||
		    !IS_ALIGNED(size, SMALL_PAGE_SIZE))
			return TEE_ERROR_BAD_PARAMETERS;

		/*
		 * TZMA supports only 2 access rights configuration
		 * for RAM ranges: secure or non-secure.
		 * Secure RAM range must start from RAM base address
		 * and non-secure RAM range must end at RAM top address.
		 */
		switch (attr) {
		case ETZPC_DECPROT_S_RW:
			if (paddr != ram_base || size > ram_size)
				return TEE_ERROR_BAD_PARAMETERS;
			tzma_r0size = ram_size / SMALL_PAGE_SIZE;
			break;
		case ETZPC_DECPROT_NS_RW:
			if (paddr < ram_base ||
			    paddr + size != ram_base + ram_size)
				return TEE_ERROR_BAD_PARAMETERS;
			tzma_r0size = (paddr - ram_base) / SMALL_PAGE_SIZE;
			break;
		default:
			EMSG("Invalid TZMA mode %"PRIu32, mode);
			return TEE_ERROR_BAD_PARAMETERS;
		}

#ifdef CFG_STM32MP15
		if (!pager_permits_decprot_config(id, attr))
			return TEE_ERROR_ACCESS_DENIED;
#endif

		if (tzma_is_locked(tzma_id)) {
			if (etzpc_get_tzma(tzma_id) != tzma_r0size) {
				EMSG("TZMA configuration locked");
				return TEE_ERROR_ACCESS_DENIED;
			}

			return TEE_SUCCESS;
		}

		etzpc_configure_tzma(tzma_id, tzma_r0size);
		if (lock)
			etzpc_lock_tzma(tzma_id);
	} else {
		EMSG("Unknown firewall ID: %"PRIu32, id);

		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_etzpc_configure(struct firewall_query *firewall)
{
	enum etzpc_decprot_attributes attr = ETZPC_DECPROT_MAX;
	uint32_t id = 0;

	if (firewall->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	id = firewall->args[0] & ETZPC_ID_MASK;

	if (id < etzpc_device->ddata.num_per_sec) {
		uint32_t mode = 0;

		/*
		 * Peripheral configuration, we assume the configuration is as
		 * follows:
		 * firewall->args[0]: Firewall configuration to apply
		 */

		mode = (firewall->args[0] & ETZPC_MODE_MASK) >>
		       ETZPC_MODE_SHIFT;
		attr = etzpc_binding2decprot(mode);

		if (decprot_is_locked(id)) {
			if (etzpc_get_decprot(id) != attr) {
				EMSG("Peripheral configuration locked");
				return TEE_ERROR_ACCESS_DENIED;
			}

			DMSG("Compliant locked config for periph %"PRIu32" - attr %s",
			     id, etzpc_decprot_strings[attr]);

			return TEE_SUCCESS;
		}

#ifdef CFG_STM32MP15
		if (!pager_permits_decprot_config(id, attr))
			return TEE_ERROR_ACCESS_DENIED;
#endif

		DMSG("Setting access config for periph %"PRIu32" - attr %s", id,
		     etzpc_decprot_strings[attr]);

		etzpc_configure_decprot(id, attr);
		if (firewall->args[0] & ETZPC_LOCK_MASK)
			etzpc_lock_decprot(id);

		return TEE_SUCCESS;
	}
	EMSG("Unknown firewall ID: %"PRIu32, id);

	return TEE_ERROR_BAD_PARAMETERS;
}

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

#ifdef CFG_STM32MP15
		if (!pager_permits_decprot_config(id, attr))
			panic();
#endif

		etzpc_configure_decprot(id, attr);

		if (lock)
			etzpc_lock_decprot(id);
	}

	clk_disable(etzpc_device->pdata.clk);
}

static TEE_Result
stm32_etzpc_dt_probe_bus(const void *fdt, int node,
			 struct firewall_controller *ctrl __maybe_unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct firewall_query *fw = NULL;
	int subnode = 0;

	DMSG("Populating %s firewall bus", ctrl->name);

	fdt_for_each_subnode(subnode, fdt, node) {
		unsigned int i = 0;

		if (fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
			continue;

		if (IS_ENABLED(CFG_INSECURE) &&
		    stm32mp_allow_probe_shared_device(fdt, subnode)) {
			DMSG("Skipping firewall attributes check for %s",
			     fdt_get_name(fdt, subnode, NULL));
			goto skip_check;
		}

		DMSG("Acquiring firewall access for %s when probing bus",
		     fdt_get_name(fdt, subnode, NULL));

		do {
			/*
			 * The access-controllers property is mandatory for
			 * firewall bus devices
			 */
			res = firewall_dt_get_by_index(fdt, subnode, i, &fw);
			if (res == TEE_ERROR_ITEM_NOT_FOUND) {
				/* Stop when nothing more to parse */
				break;
			} else if (res) {
				EMSG("%s: Error on node %s: %#"PRIx32,
				     ctrl->name,
				     fdt_get_name(fdt, subnode, NULL), res);
				panic();
			}

			res = firewall_acquire_access(fw);
			if (res) {
				EMSG("%s: %s not accessible: %#"PRIx32,
				     ctrl->name,
				     fdt_get_name(fdt, subnode, NULL), res);
				panic();
			}

			firewall_put(fw);
			i++;
		} while (true);

skip_check:
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	return TEE_SUCCESS;
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
	if (!etzpc_device->pdata.periph_cfg)
		return TEE_ERROR_OUT_OF_MEMORY;

	etzpc_device->pdata.tzma_cfg =
		calloc(etzpc_device->ddata.num_tzma,
		       sizeof(*etzpc_device->pdata.tzma_cfg));
	if (!etzpc_device->pdata.tzma_cfg) {
		free(etzpc_device->pdata.periph_cfg);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static const struct firewall_controller_ops firewall_ops = {
	.set_conf = stm32_etzpc_configure,
	.set_memory_conf = stm32_etzpc_configure_memory,
	.check_access = stm32_etzpc_check_access,
	.acquire_access = stm32_etzpc_acquire_access,
	.acquire_memory_access = stm32_etzpc_acquire_memory_access,
};

static TEE_Result stm32_etzpc_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct firewall_controller *controller = NULL;

	etzpc_device = calloc(1, sizeof(*etzpc_device));
	if (!etzpc_device)
		panic();

	res = init_etzpc_from_dt(fdt, node);
	if (res) {
		free(etzpc_device->pdata.periph_cfg);
		free(etzpc_device->pdata.tzma_cfg);
		free(etzpc_device->pdata.name);
		free(etzpc_device);
		free(controller);
		return res;
	}

	controller = calloc(1, sizeof(*controller));
	if (!controller)
		panic();

	controller->base = &etzpc_device->pdata.base;
	controller->name = etzpc_device->pdata.name;
	controller->priv = etzpc_device;
	controller->ops = &firewall_ops;

	res = firewall_dt_controller_register(fdt, node, controller);
	if (res)
		panic("Cannot register ETZPC as a firewall controller");

	fdt_etzpc_conf_decprot(fdt, node);

	res = stm32_etzpc_dt_probe_bus(fdt, node, controller);
	if (res)
		panic("Cannot populate bus");

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
