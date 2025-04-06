// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/firewall.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32_risaf.h>
#include <dt-bindings/firewall/stm32mp25-risaf.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <util.h>

/* RISAF general registers (base relative) */
#define _RISAF_CR			U(0x00)
#define _RISAF_SR			U(0x04)
#define _RISAF_IASR			U(0x08)
#define _RISAF_IACR			U(0xC)
#define _RISAF_IAESR0			U(0x20)
#define _RISAF_IADDR0			U(0x24)
#define _RISAF_IAESR1			U(0x28)
#define _RISAF_IADDR1			U(0x2C)
#define _RISAF_KEYR			U(0x30)
#define _RISAF_HWCFGR			U(0xFF0)
#define _RISAF_VERR			U(0xFF4)
#define _RISAF_IPIDR			U(0xFF8)
#define _RISAF_SIDR			U(0xFFC)

/* RISAF general register field description */
/* _RISAF_CR register fields */
#define _RISAF_CR_GLOCK			BIT(0)
/* _RISAF_SR register fields */
#define _RISAF_SR_KEYVALID		BIT(0)
#define _RISAF_SR_KEYRDY		BIT(1)
#define _RISAF_SR_ENCDIS		BIT(2)
/* _RISAF_IACR register fields */
#define _RISAF_IACR_CAEF		BIT(0)
#define _RISAF_IACR_IAEF0		BIT(1)
#define _RISAF_IACR_IAEF1		BIT(2)
/* _RISAF_HWCFGR register fields */
#define _RISAF_HWCFGR_CFG1_SHIFT	U(0)
#define _RISAF_HWCFGR_CFG1_MASK		GENMASK_32(7, 0)
#define _RISAF_HWCFGR_CFG2_SHIFT	U(8)
#define _RISAF_HWCFGR_CFG2_MASK		GENMASK_32(15, 8)
#define _RISAF_HWCFGR_CFG3_SHIFT	U(16)
#define _RISAF_HWCFGR_CFG3_MASK		GENMASK_32(23, 16)
#define _RISAF_HWCFGR_CFG4_SHIFT	U(24)
#define _RISAF_HWCFGR_CFG4_MASK		GENMASK_32(31, 24)
/* _RISAF_VERR register fields */
#define _RISAF_VERR_MINREV_SHIFT	U(0)
#define _RISAF_VERR_MINREV_MASK		GENMASK_32(3, 0)
#define _RISAF_VERR_MAJREV_SHIFT	U(4)
#define _RISAF_VERR_MAJREV_MASK		GENMASK_32(7, 4)

/* RISAF region registers (base relative) */
#define _RISAF_REG_BASE			U(0x40)
#define _RISAF_REG_SIZE			U(0x40)
#define _RISAF_REG(n)			(_RISAF_REG_BASE + \
					 (((n) - 1) * _RISAF_REG_SIZE))
#define _RISAF_REG_CFGR_OFFSET		U(0x0)
#define _RISAF_REG_CFGR(n)		(_RISAF_REG(n) + _RISAF_REG_CFGR_OFFSET)
#define _RISAF_REG_STARTR_OFFSET	U(0x4)
#define _RISAF_REG_STARTR(n)		(_RISAF_REG(n) + \
					 _RISAF_REG_STARTR_OFFSET)
#define _RISAF_REG_ENDR_OFFSET		U(0x8)
#define _RISAF_REG_ENDR(n)		(_RISAF_REG(n) + _RISAF_REG_ENDR_OFFSET)
#define _RISAF_REG_CIDCFGR_OFFSET	U(0xC)
#define _RISAF_REG_CIDCFGR(n)		(_RISAF_REG(n) + \
					 _RISAF_REG_CIDCFGR_OFFSET)

/* RISAF region register field description */
/* _RISAF_REG_CFGR(n) register fields */
#define _RISAF_REG_CFGR_BREN_SHIFT	U(0)
#define _RISAF_REG_CFGR_BREN		BIT(_RISAF_REG_CFGR_BREN_SHIFT)
#define _RISAF_REG_CFGR_SEC_SHIFT	U(8)
#define _RISAF_REG_CFGR_SEC		BIT(_RISAF_REG_CFGR_SEC_SHIFT)
#define _RISAF_REG_CFGR_ENC_SHIFT	U(15)
#define _RISAF_REG_CFGR_ENC		BIT(_RISAF_REG_CFGR_ENC_SHIFT)
#define _RISAF_REG_CFGR_PRIVC_SHIFT	U(16)
#define _RISAF_REG_CFGR_PRIVC_MASK	GENMASK_32(23, 16)
#define _RISAF_REG_CFGR_ALL_MASK	(_RISAF_REG_CFGR_BREN | \
					 _RISAF_REG_CFGR_SEC | \
					 _RISAF_REG_CFGR_ENC | \
					 _RISAF_REG_CFGR_PRIVC_MASK)

/* _RISAF_REG_CIDCFGR(n) register fields */
#define _RISAF_REG_CIDCFGR_RDENC_SHIFT	U(0)
#define _RISAF_REG_CIDCFGR_RDENC_MASK	GENMASK_32(7, 0)
#define _RISAF_REG_CIDCFGR_WRENC_SHIFT	U(16)
#define _RISAF_REG_CIDCFGR_WRENC_MASK	GENMASK_32(23, 16)
#define _RISAF_REG_CIDCFGR_ALL_MASK	(_RISAF_REG_CIDCFGR_RDENC_MASK | \
					 _RISAF_REG_CIDCFGR_WRENC_MASK)
#define _RISAF_REG_READ_OK(reg, cid) \
	((reg) & BIT((cid) + _RISAF_REG_CIDCFGR_RDENC_SHIFT))
#define _RISAF_REG_WRITE_OK(reg, cid)	\
	((reg) & BIT((cid) + _RISAF_REG_CIDCFGR_WRENC_SHIFT))

#define _RISAF_GET_REGION_ID(cfg)	((cfg) & DT_RISAF_REG_ID_MASK)

#define _RISAF_NB_CID_SUPPORTED		U(8)

/**
 * struct stm32_risaf_region - RISAF memory region
 *
 * @addr: Region base address.
 * @len: Length of the memory region.
 * @cfg: Region configuration.
 */
struct stm32_risaf_region {
	paddr_t addr;
	size_t len;
	uint32_t cfg;
};

/**
 * struct stm32_risaf_pdata - RISAF platform data
 *
 * @base: Base address of the RISAF instance.
 * @clock: Clock of the RISAF.
 * @regions: Number of memory regions, defined by the device tree configuration.
 * @risaf_name: Name of the RISAF instance
 * @nregions: Number of memory regions found in the device tree.
 * @conf_lock: State whether the RISAF configuration is locked.
 * @mem_base: Base address of the memory range covered by the RISAF instance.
 * @mem_size: Size of the memory range covered by the RISAF instance.
 * @enc_supported: If true, the RISAF instance supports encryption of the memory
 * regions.
 */
struct stm32_risaf_pdata {
	struct io_pa_va base;
	struct clk *clock;
	struct stm32_risaf_region *regions;
	char risaf_name[20];
	unsigned int nregions;
	unsigned int conf_lock;
	paddr_t mem_base;
	size_t mem_size;
	bool enc_supported;
};

/**
 * struct stm32_risaf_ddata - RISAF driver data
 *
 * @mask_regions: Number of address bits to match when determining access to a
 * base region or subregion (WIDTH).
 * @max_base_regions: Number of subdivision of the memory range (A.K.A memory
 * regions) supported by the RISAF instance.
 * @granularity: Length of the smallest possible region size.
 */
struct stm32_risaf_ddata {
	uint32_t mask_regions;
	uint32_t max_base_regions;
	uint32_t granularity;
};

struct stm32_risaf_instance {
	struct stm32_risaf_pdata pdata;
	struct stm32_risaf_ddata *ddata;

	SLIST_ENTRY(stm32_risaf_instance) link;
};

struct stm32_risaf_version {
	uint32_t major;
	uint32_t minor;
	uint32_t ip_id;
	uint32_t size_id;
};

/**
 * struct stm32_risaf_compat_data  - Describes RISAF associated data
 * for compatible list.
 *
 * @supported_encryption:	identify RISAF encryption capabilities.
 */
struct stm32_risaf_compat_data {
	bool supported_encryption;
};

static bool is_tdcid;

static const struct stm32_risaf_compat_data stm32_risaf_compat = {
	.supported_encryption = false,
};

static const struct stm32_risaf_compat_data stm32_risaf_enc_compat = {
	.supported_encryption = true,
};

static SLIST_HEAD(, stm32_risaf_instance) risaf_list =
		SLIST_HEAD_INITIALIZER(risaf_list);

static vaddr_t risaf_base(struct stm32_risaf_instance *risaf)
{
	return io_pa_or_va_secure(&risaf->pdata.base, 1);
}

static uint32_t stm32_risaf_get_region_config(uint32_t cfg)
{
	return SHIFT_U32((cfg & DT_RISAF_EN_MASK) >> DT_RISAF_EN_SHIFT,
			 _RISAF_REG_CFGR_BREN_SHIFT) |
	       SHIFT_U32((cfg & DT_RISAF_SEC_MASK) >> DT_RISAF_SEC_SHIFT,
			 _RISAF_REG_CFGR_SEC_SHIFT) |
	       SHIFT_U32((cfg & DT_RISAF_ENC_MASK) >> (DT_RISAF_ENC_SHIFT + 1),
			 _RISAF_REG_CFGR_ENC_SHIFT) |
	       SHIFT_U32((cfg & DT_RISAF_PRIV_MASK) >> DT_RISAF_PRIV_SHIFT,
			 _RISAF_REG_CFGR_PRIVC_SHIFT);
}

static uint32_t stm32_risaf_get_region_cid_config(uint32_t cfg)
{
	return SHIFT_U32((cfg & DT_RISAF_WRITE_MASK) >> DT_RISAF_WRITE_SHIFT,
			 _RISAF_REG_CIDCFGR_WRENC_SHIFT) |
	       SHIFT_U32((cfg & DT_RISAF_READ_MASK) >> DT_RISAF_READ_SHIFT,
			 _RISAF_REG_CIDCFGR_RDENC_SHIFT);
}

void stm32_risaf_clear_illegal_access_flags(void)
{
	struct stm32_risaf_instance *risaf = NULL;

	SLIST_FOREACH(risaf, &risaf_list, link) {
		vaddr_t base = io_pa_or_va_secure(&risaf->pdata.base, 1);

		if (!io_read32(base + _RISAF_IASR))
			continue;

		io_write32(base + _RISAF_IACR, _RISAF_IACR_CAEF |
			   _RISAF_IACR_IAEF0 | _RISAF_IACR_IAEF1);
	}
}

void stm32_risaf_print_erroneous_data(void)
{
	struct stm32_risaf_instance *risaf = NULL;

	if (!IS_ENABLED(CFG_TEE_CORE_DEBUG))
		return;

	SLIST_FOREACH(risaf, &risaf_list, link) {
		vaddr_t base = io_pa_or_va_secure(&risaf->pdata.base, 1);

		/* Check if faulty address on this RISAF */
		if (!io_read32(base + _RISAF_IASR))
			continue;

		IMSG("\n\nDUMPING DATA FOR %s\n\n", risaf->pdata.risaf_name);
		IMSG("=====================================================");
		IMSG("Status register (IAESR0): %#"PRIx32,
		     io_read32(base + _RISAF_IAESR0));

		/* Reserved if dual port feature not available */
		if (io_read32(base + _RISAF_IAESR1))
			IMSG("Status register Dual Port (IAESR1) %#"PRIx32,
			     io_read32(base + _RISAF_IAESR1));

		IMSG("-----------------------------------------------------");
		if (virt_to_phys((void *)base) == RISAF4_BASE) {
			IMSG("Faulty address (IADDR0): %#"PRIxPA,
			     risaf->pdata.mem_base +
			     io_read32(base + _RISAF_IADDR0));

			/* Reserved if dual port feature not available */
			if (io_read32(base + _RISAF_IADDR1))
				IMSG("Dual port faulty address (IADDR1): %#"PRIxPA,
				     risaf->pdata.mem_base +
				     io_read32(base + _RISAF_IADDR1));
		} else {
			IMSG("Faulty address (IADDR0): %#"PRIx32,
			     io_read32(base + _RISAF_IADDR0));

			/* Reserved if dual port feature not available */
			if (io_read32(base + _RISAF_IADDR1))
				IMSG("Dual port faulty address (IADDR1): %#"PRIx32,
				     io_read32(base + _RISAF_IADDR1));
		}

		IMSG("=====================================================\n");
	};
}

static __maybe_unused
bool risaf_is_hw_encryption_enabled(struct stm32_risaf_instance *risaf)
{
	return (io_read32(risaf_base(risaf) + _RISAF_SR) &
		_RISAF_SR_ENCDIS) != _RISAF_SR_ENCDIS;
}

static TEE_Result
risaf_check_region_boundaries(struct stm32_risaf_instance *risaf,
			      struct stm32_risaf_region *region)
{
	if (!core_is_buffer_inside(region->addr, region->len,
				   risaf->pdata.mem_base,
				   risaf->pdata.mem_size)) {
		EMSG("Region %#"PRIxPA"..%#"PRIxPA" outside RISAF area %#"PRIxPA"...%#"PRIxPA,
		     region->addr, region->addr + region->len - 1,
		     risaf->pdata.mem_base,
		     risaf->pdata.mem_base + risaf->pdata.mem_size - 1);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!risaf->ddata->granularity ||
	    (region->addr % risaf->ddata->granularity) ||
	    (region->len % risaf->ddata->granularity)) {
		EMSG("RISAF %#"PRIxPA": start/end address granularity not respected",
		     risaf->pdata.base.pa);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result
risaf_check_overlap(struct stm32_risaf_instance *risaf __maybe_unused,
		    struct stm32_risaf_region *region, unsigned int index)
{
	unsigned int i = 0;

	for (i = 0; i < index; i++) {
		/* Skip region if there's no configuration */
		if (!region[i].cfg)
			continue;

		if (core_is_buffer_intersect(region[index].addr,
					     region[index].len,
					     region[i].addr,
					     region[i].len)) {
			EMSG("RISAF %#"PRIxPA": Regions %u and %u overlap",
			     risaf->pdata.base.pa, index, i);
			return TEE_ERROR_GENERIC;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result risaf_configure_region(struct stm32_risaf_instance *risaf,
					 uint32_t region_id, uint32_t cfg,
					 uint32_t cid_cfg, paddr_t saddr,
					 paddr_t eaddr)
{
	uint32_t mask = risaf->ddata->mask_regions;
	vaddr_t base = risaf_base(risaf);

	if (cfg & _RISAF_REG_CFGR_ENC) {
		if (!risaf->pdata.enc_supported) {
			EMSG("RISAF %#"PRIxPA": encryption feature error",
			     risaf->pdata.base.pa);
			return TEE_ERROR_GENERIC;
		}

		if ((cfg & _RISAF_REG_CFGR_SEC) != _RISAF_REG_CFGR_SEC) {
			EMSG("RISAF %#"PRIxPA": encryption on non-secure area",
			     risaf->pdata.base.pa);
			return TEE_ERROR_GENERIC;
		}
	}

	io_clrbits32(base + _RISAF_REG_CFGR(region_id), _RISAF_REG_CFGR_BREN);

	io_clrsetbits32(base + _RISAF_REG_STARTR(region_id), mask,
			(saddr - risaf->pdata.mem_base) & mask);
	io_clrsetbits32(base + _RISAF_REG_ENDR(region_id), mask,
			(eaddr - risaf->pdata.mem_base) & mask);
	io_clrsetbits32(base + _RISAF_REG_CIDCFGR(region_id),
			_RISAF_REG_CIDCFGR_ALL_MASK,
			cid_cfg & _RISAF_REG_CIDCFGR_ALL_MASK);

	io_clrsetbits32(base + _RISAF_REG_CFGR(region_id),
			_RISAF_REG_CFGR_ALL_MASK,
			cfg & _RISAF_REG_CFGR_ALL_MASK);

	DMSG("RISAF %#"PRIxPA": region %02"PRIu32" - start %#"PRIxPA
	     "- end %#"PRIxPA" - cfg %#08"PRIx32" - cidcfg %#08"PRIx32,
	     risaf->pdata.base.pa, region_id,
	     risaf->pdata.mem_base +
	     io_read32(base + _RISAF_REG_STARTR(region_id)),
	     risaf->pdata.mem_base +
	     io_read32(base + _RISAF_REG_ENDR(region_id)),
	     io_read32(base + _RISAF_REG_CFGR(region_id)),
	     io_read32(base + _RISAF_REG_CIDCFGR(region_id)));

	return TEE_SUCCESS;
}

static void risaf_print_version(struct stm32_risaf_instance *risaf)
{
	vaddr_t base = risaf_base(risaf);
	struct stm32_risaf_version __maybe_unused version = {
		.major = (io_read32(base + _RISAF_VERR) &
			  _RISAF_VERR_MAJREV_MASK) >> _RISAF_VERR_MAJREV_SHIFT,
		.minor = (io_read32(base + _RISAF_VERR) &
			  _RISAF_VERR_MINREV_MASK) >> _RISAF_VERR_MINREV_SHIFT,
		.ip_id = io_read32(base + _RISAF_IPIDR),
		.size_id = io_read32(base + _RISAF_SIDR)
	};

	DMSG("RISAF %#"PRIxPA" version %"PRIu32".%"PRIu32", ip%#"PRIx32" size%#"PRIx32,
	     risaf->pdata.base.pa, version.major, version.minor, version.ip_id,
	     version.size_id);
}

static __maybe_unused
void stm32_risaf_lock(struct stm32_risaf_instance *risaf)
{
	assert(risaf);

	io_setbits32(risaf_base(risaf) + _RISAF_CR, _RISAF_CR_GLOCK);
}

static __maybe_unused
void stm32_risaf_is_locked(struct stm32_risaf_instance *risaf, bool *state)
{
	assert(risaf);

	*state = (io_read32(risaf_base(risaf) + _RISAF_CR) &
		  _RISAF_CR_GLOCK) == _RISAF_CR_GLOCK;
}

static TEE_Result stm32_risaf_init_ddata(struct stm32_risaf_instance *risaf)
{
	vaddr_t base = risaf_base(risaf);
	uint32_t granularity = 0;
	uint32_t mask_lsb = 0;
	uint32_t mask_msb = 0;
	uint32_t hwcfgr = 0;

	risaf->ddata = calloc(1, sizeof(*risaf->ddata));
	if (!risaf->ddata)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Get address mask depending on RISAF instance HW configuration */
	hwcfgr =  io_read32(base + _RISAF_HWCFGR);
	mask_lsb = (hwcfgr & _RISAF_HWCFGR_CFG3_MASK) >>
		   _RISAF_HWCFGR_CFG3_SHIFT;
	mask_msb = mask_lsb + ((hwcfgr & _RISAF_HWCFGR_CFG4_MASK) >>
			       _RISAF_HWCFGR_CFG4_SHIFT) - 1U;
	risaf->ddata->mask_regions = GENMASK_32(mask_msb, mask_lsb);
	risaf->ddata->max_base_regions = (hwcfgr & _RISAF_HWCFGR_CFG1_MASK) >>
					 _RISAF_HWCFGR_CFG1_SHIFT;

	/* Get IP region granularity */
	granularity = io_read32(risaf_base(risaf) + _RISAF_HWCFGR);
	granularity = BIT((granularity & _RISAF_HWCFGR_CFG3_MASK) >>
			  _RISAF_HWCFGR_CFG3_SHIFT);
	risaf->ddata->granularity = granularity;

	return TEE_SUCCESS;
}

static TEE_Result stm32_risaf_pm_resume(struct stm32_risaf_instance *risaf)
{
	struct stm32_risaf_region *regions = risaf->pdata.regions;
	size_t i = 0;

	for (i = 0; i < risaf->pdata.nregions; i++) {
		uint32_t id = _RISAF_GET_REGION_ID(regions[i].cfg);
		paddr_t start_addr = 0;
		paddr_t end_addr = 0;
		uint32_t cid_cfg = 0;
		uint32_t cfg = 0;

		if (!id)
			continue;

		cfg = stm32_risaf_get_region_config(regions[i].cfg);
		cid_cfg = stm32_risaf_get_region_cid_config(regions[i].cfg);
		start_addr = regions[i].addr;
		end_addr = start_addr + regions[i].len - 1U;
		if (risaf_configure_region(risaf, id, cfg, cid_cfg,
					   start_addr, end_addr))
			panic();
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_risaf_pm_suspend(struct stm32_risaf_instance *risaf)
{
	vaddr_t base = io_pa_or_va_secure(&risaf->pdata.base, 1);
	size_t i = 0;

	for (i = 0; i < risaf->pdata.nregions; i++) {
		uint32_t id = _RISAF_GET_REGION_ID(risaf->pdata.regions[i].cfg);
		struct stm32_risaf_region *region = risaf->pdata.regions + i;
		paddr_t start_addr = 0;
		paddr_t end_addr = 0;
		uint32_t cid_cfg = 0;
		uint32_t priv = 0;
		uint32_t rden = 0;
		uint32_t wren = 0;
		uint32_t cfg = 0;
		uint32_t enc = 0;
		uint32_t sec = 0;
		uint32_t en = 0;

		/* Skip region not defined in DT, not configured in probe */
		if (!id)
			continue;

		cfg = io_read32(base + _RISAF_REG_CFGR(id));
		en = cfg & _RISAF_REG_CFGR_BREN;
		sec = (cfg & _RISAF_REG_CFGR_SEC) >> _RISAF_REG_CFGR_SEC_SHIFT;
		enc = (cfg & _RISAF_REG_CFGR_ENC) >> _RISAF_REG_CFGR_ENC_SHIFT;
		priv = (cfg & _RISAF_REG_CFGR_PRIVC_MASK) >>
		       _RISAF_REG_CFGR_PRIVC_SHIFT;

		cid_cfg = io_read32(base + _RISAF_REG_CIDCFGR(id));
		rden = cid_cfg & _RISAF_REG_CIDCFGR_RDENC_MASK;
		wren = (cid_cfg & _RISAF_REG_CIDCFGR_WRENC_MASK) >>
		       _RISAF_REG_CIDCFGR_WRENC_SHIFT;

		region->cfg = id | SHIFT_U32(en, DT_RISAF_EN_SHIFT) |
			      SHIFT_U32(sec, DT_RISAF_SEC_SHIFT) |
			      SHIFT_U32(enc, DT_RISAF_ENC_SHIFT + 1) |
			      SHIFT_U32(priv, DT_RISAF_PRIV_SHIFT) |
			      SHIFT_U32(rden, DT_RISAF_READ_SHIFT) |
			      SHIFT_U32(wren, DT_RISAF_WRITE_SHIFT);
		start_addr = io_read32(base + _RISAF_REG_STARTR(id));
		end_addr = io_read32(base + _RISAF_REG_ENDR(id));
		region->addr = start_addr + risaf->pdata.mem_base;
		region->len = end_addr - start_addr + 1;
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32_risaf_pm(enum pm_op op, unsigned int pm_hint,
	       const struct pm_callback_handle *pm_handle)
{
	struct stm32_risaf_instance *risaf = pm_handle->handle;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(risaf);

	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT))
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME)
		res = stm32_risaf_pm_resume(risaf);
	else
		res = stm32_risaf_pm_suspend(risaf);

	return res;
}

static TEE_Result stm32_risaf_acquire_access(struct firewall_query *fw,
					     paddr_t paddr, size_t size,
					     bool read, bool write)
{
	struct stm32_risaf_instance *risaf = NULL;
	struct stm32_risaf_region *region = NULL;
	uint32_t cidcfgr = 0;
	unsigned int i = 0;
	uint32_t cfgr = 0;
	vaddr_t base = 0;
	uint32_t id = 0;

	assert(fw->ctrl->priv && (read || write));

	if (paddr == TZDRAM_BASE && size == TZDRAM_SIZE)
		return TEE_SUCCESS;

	risaf = fw->ctrl->priv;
	base = risaf_base(risaf);

	if (fw->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * RISAF region configuration, we assume the query is as
	 * follows:
	 * firewall->args[0]: Region configuration
	 */
	id = _RISAF_GET_REGION_ID(fw->args[0]);

	if (!id || id >= risaf->pdata.nregions)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < risaf->pdata.nregions; i++) {
		if (id == _RISAF_GET_REGION_ID(risaf->pdata.regions[i].cfg)) {
			region = &risaf->pdata.regions[i];
			if (region->addr != paddr || region->len != size)
				return TEE_ERROR_GENERIC;
			break;
		}
	}
	if (!region)
		return TEE_ERROR_ITEM_NOT_FOUND;

	cfgr = io_read32(base + _RISAF_REG_CFGR(id));
	cidcfgr = io_read32(base + _RISAF_REG_CIDCFGR(id));

	/*
	 * Access is denied if the region is disabled and OP-TEE does not run as
	 * TDCID, or the region is not secure, or if it is not accessible in
	 * read and/or write mode, if requested, by OP-TEE CID.
	 */
	if (!(cfgr & _RISAF_REG_CFGR_BREN) && !is_tdcid)
		return TEE_ERROR_ACCESS_DENIED;

	if ((cfgr & _RISAF_REG_CFGR_BREN) &&
	    (!(cfgr & _RISAF_REG_CFGR_SEC) ||
	     (read && !_RISAF_REG_READ_OK(cidcfgr, RIF_CID1)) ||
	     (write && !_RISAF_REG_WRITE_OK(cidcfgr, RIF_CID1)))) {
		return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_risaf_reconfigure_region(struct firewall_query *fw,
						 paddr_t paddr, size_t size)
{
	struct stm32_risaf_instance *risaf = NULL;
	struct stm32_risaf_region *region = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;
	uint32_t q_cfg = 0;
	unsigned int i = 0;
	uint32_t id = 0;

	assert(fw->ctrl->priv);

	risaf = fw->ctrl->priv;

	if (fw->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * RISAF region configuration, we assume the query is as
	 * follows:
	 * firewall->args[0]: Region configuration
	 */
	q_cfg = fw->args[0];
	id = _RISAF_GET_REGION_ID(q_cfg);

	if (!id || id >= risaf->pdata.nregions)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < risaf->pdata.nregions; i++) {
		if (id == _RISAF_GET_REGION_ID(risaf->pdata.regions[i].cfg)) {
			region = &risaf->pdata.regions[i];
			if (region->addr != paddr || region->len != size)
				return TEE_ERROR_GENERIC;
			break;
		}
	}
	if (!region)
		return TEE_ERROR_ITEM_NOT_FOUND;

	DMSG("Reconfiguring %s region ID: %"PRIu32, risaf->pdata.risaf_name,
	     id);

	exceptions = cpu_spin_lock_xsave(&risaf->pdata.conf_lock);
	res = risaf_configure_region(risaf, id,
				     stm32_risaf_get_region_config(q_cfg),
				     stm32_risaf_get_region_cid_config(q_cfg),
				     region->addr,
				     region->addr + region->len - 1);

	cpu_spin_unlock_xrestore(&risaf->pdata.conf_lock, exceptions);

	return res;
}

static const struct firewall_controller_ops firewall_ops = {
	.acquire_memory_access = stm32_risaf_acquire_access,
	.set_memory_conf = stm32_risaf_reconfigure_region,
};

static TEE_Result stm32_risaf_probe(const void *fdt, int node,
				    const void *compat_data)
{
	const struct stm32_risaf_compat_data *compat = compat_data;
	struct firewall_controller *controller = NULL;
	struct stm32_risaf_instance *risaf = NULL;
	struct stm32_risaf_region *regions = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_info = { };
	const fdt32_t *conf_list = NULL;
	const fdt64_t *cuint = NULL;
	unsigned int nregions = 0;
	unsigned int i = 0;
	int len = 0;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	if (!is_tdcid)
		return TEE_SUCCESS;

	risaf = calloc(1, sizeof(*risaf));
	if (!risaf)
		return TEE_ERROR_OUT_OF_MEMORY;

	fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.reg_size == DT_INFO_INVALID_REG_SIZE) {
		free(risaf);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	risaf->pdata.base.pa = dt_info.reg;
	io_pa_or_va_secure(&risaf->pdata.base, dt_info.reg_size);

	risaf->pdata.enc_supported = compat->supported_encryption;

	res = clk_dt_get_by_index(fdt, node, 0, &risaf->pdata.clock);
	if (!risaf->pdata.clock)
		goto err;

	conf_list = fdt_getprop(fdt, node, "memory-region", &len);
	if (!conf_list) {
		DMSG("RISAF %#"PRIxPA": No configuration in DT, use default",
		     risaf->pdata.base.pa);
		free(risaf);
		return TEE_SUCCESS;
	}

	nregions = (unsigned int)len / sizeof(uint32_t);

	/* Silently allow unexpected truncated names */
	strncpy(risaf->pdata.risaf_name, fdt_get_name(fdt, node, NULL),
		sizeof(risaf->pdata.risaf_name) - 1);

	res = clk_enable(risaf->pdata.clock);
	if (res)
		goto err;

	res = stm32_risaf_init_ddata(risaf);
	if (res)
		goto err_clk;

	risaf_print_version(risaf);

	cuint = fdt_getprop(fdt, node, "st,mem-map", &len);
	if (!cuint || (size_t)len != sizeof(*cuint) * 2)
		panic();

	risaf->pdata.mem_base = (paddr_t)fdt64_to_cpu(*cuint);
	risaf->pdata.mem_size = (size_t)fdt64_to_cpu(*(cuint + 1));

	regions = calloc(nregions, sizeof(*regions));
	if (nregions && !regions) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_ddata;
	}

	DMSG("RISAF %#"PRIxPA" memory range: %#"PRIxPA" - %#"PRIxPA,
	     risaf->pdata.base.pa, risaf->pdata.mem_base,
	     risaf->pdata.mem_base + risaf->pdata.mem_size - 1);

	for (i = 0; i < nregions; i++) {
		const fdt32_t *prop = NULL;
		paddr_t start_addr = 0;
		paddr_t end_addr = 0;
		uint32_t cid_cfg = 0;
		uint32_t phandle = 0;
		uint32_t cfg = 0;
		uint32_t id = 0;
		int pnode = 0;

		phandle = fdt32_to_cpu(*(conf_list + i));
		pnode = fdt_node_offset_by_phandle(fdt, phandle);
		if (pnode < 0)
			continue;

		if (fdt_reg_info(fdt, pnode, &regions[i].addr,
				 &regions[i].len)) {
			EMSG("Invalid config in node %s",
			     fdt_get_name(fdt, pnode, NULL));
			panic();
		}

		if (!regions[i].len)
			continue;

		/*
		 * The secure bootloader is in charge of configuring RISAF
		 * related to OP-TEE secure memory. Therefore, skip OP-TEE
		 * region so that RISAF configuration cannot interfere with
		 * OP-TEE execution flow.
		 */
		if (regions[i].addr == TZDRAM_BASE &&
		    regions[i].len == TZDRAM_SIZE) {
			continue;
		}

		prop = fdt_getprop(fdt, pnode, "st,protreg", NULL);
		if (!prop)
			continue;

		regions[i].cfg = fdt32_to_cpu(*prop);

		if (risaf_check_region_boundaries(risaf, &regions[i]) ||
		    risaf_check_overlap(risaf, regions, i))
			panic();

		id = _RISAF_GET_REGION_ID(regions[i].cfg);
		assert(id < risaf->ddata->max_base_regions);

		cfg = stm32_risaf_get_region_config(regions[i].cfg);

		cid_cfg = stm32_risaf_get_region_cid_config(regions[i].cfg);

		start_addr = regions[i].addr;
		end_addr = start_addr + regions[i].len - 1U;

		if (risaf_configure_region(risaf, id, cfg, cid_cfg,
					   start_addr, end_addr))
			panic();
	}

	controller = calloc(1, sizeof(*controller));
	if (!controller)
		panic();

	controller->base = &risaf->pdata.base;
	controller->name = risaf->pdata.risaf_name;
	controller->priv = risaf;
	controller->ops = &firewall_ops;

	risaf->pdata.regions = regions;
	risaf->pdata.nregions = nregions;

	SLIST_INSERT_HEAD(&risaf_list, risaf, link);

	res = firewall_dt_controller_register(fdt, node, controller);
	if (res)
		panic();

	register_pm_core_service_cb(stm32_risaf_pm, risaf, "stm32-risaf");

	return TEE_SUCCESS;

err_ddata:
	free(risaf->ddata);
err_clk:
	clk_disable(risaf->pdata.clock);
err:
	free(risaf);
	return res;
}

static const struct dt_device_match risaf_match_table[] = {
	{
		.compatible = "st,stm32mp25-risaf",
		.compat_data = &stm32_risaf_compat,
	},
	{
		.compatible = "st,stm32mp25-risaf-enc",
		.compat_data = &stm32_risaf_enc_compat,
	},
	{ }
};

DEFINE_DT_DRIVER(risaf_dt_driver) = {
	.name = "stm32-risaf",
	.match_table = risaf_match_table,
	.probe = stm32_risaf_probe,
};
