// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/firewall.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32_risab.h>
#include <dt-bindings/firewall/stm32mp25-risab.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <kernel/tee_misc.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string_ext.h>
#include <stm32_sysconf.h>
#include <util.h>

#define _RISAB_CR				U(0x0)
#define _RISAB_IASR				U(0x8)
#define _RISAB_IACR				U(0xC)
#define _RISAB_RCFGLOCKR			U(0x10)
#define _RISAB_IAESR				U(0x20)
#define _RISAB_IADDR				U(0x24)
#define _RISAB_PGy_SECCFGR(y)			(U(0x100) + (0x4 * (y)))
#define _RISAB_PGy_PRIVCFGR(y)			(U(0x200) + (0x4 * (y)))
#define _RISAB_RISAB_PGy_C2PRIVCFGR(y)		(U(0x600) + (0x4 * (y)))
#define _RISAB_CIDxPRIVCFGR(x)			(U(0x800) + (0x20 * (x)))
#define _RISAB_CIDxRDCFGR(x)			(U(0x808) + (0x20 * (x)))
#define _RISAB_CIDxWRCFGR(x)			(U(0x810) + (0x20 * (x)))
#define _RISAB_PGy_CIDCFGR(y)			(U(0xA00) + (0x4 * (y)))
#define _RISAB_HWCFGR3				U(0xFE8)
#define _RISAB_HWCFGR2				U(0xFEC)
#define _RISAB_HWCFGR1				U(0xFF0)
#define _RISAB_VERR				U(0xFF4)
#define _RISAB_IPIDR				U(0xFF8)
#define _RISAB_SIDR				U(0xFFC)

/* RISAB_CR bitfields */
#define _RISAB_CR_SRWIAD			BIT(31)

/* RISAB_IACR bitfields */
#define _RISAB_IACR_CAEF			BIT(0)
#define _RISAB_IACR_IAEF			BIT(1)
#define _RISAB_IACR_MASK			(_RISAB_IACR_CAEF | \
						 _RISAB_IACR_IAEF)

/* Define RISAB_PG_SECCFGR bitfields */
#define _RISAB_PG_SECCFGR_MASK			GENMASK_32(7, 0)

/* Define RISAB_PG_PRIVCFGR bitfields */
#define _RISAB_PG_PRIVCFGR_MASK			GENMASK_32(7, 0)

/* CIDCFGR bitfields */
#define _RISAB_PG_CIDCFGR_CFEN			BIT(0)
#define _RISAB_PG_CIDCFGR_DCEN			BIT(2)
#define _RISAB_PG_CIDCFGR_DDCID_SHIFT		U(4)
#define _RISAB_PG_CIDCFGR_DDCID_MASK		GENMASK_32(6, 4)
#define _RISAB_PG_CIDCFGR_CONF_MASK		(_RISAB_PG_CIDCFGR_CFEN | \
						 _RISAB_PG_CIDCFGR_DCEN | \
						 _RISAB_PG_CIDCFGR_DDCID_MASK)

/* Miscellaneous */
#define _RISAB_NB_PAGES_MAX			U(32)
#define _RISAB_PAGE_SIZE			U(0x1000)
#define _RISAB_NB_MAX_CID_SUPPORTED		U(7)

#define RISAB_NAME_LEN_MAX			U(20)

struct mem_region {
	paddr_t base;
	size_t size;
};

struct stm32_risab_rif_conf {
	unsigned int first_page;
	unsigned int nb_pages_cfged;
	uint32_t plist[_RISAB_NB_MAX_CID_SUPPORTED];
	uint32_t rlist[_RISAB_NB_MAX_CID_SUPPORTED];
	uint32_t wlist[_RISAB_NB_MAX_CID_SUPPORTED];
	uint32_t cidcfgr;
	uint32_t dprivcfgr;
	uint32_t seccfgr;
};

struct stm32_risab_pdata {
	unsigned int nb_regions_cfged;
	struct clk *clock;
	struct mem_region region_cfged;
	struct stm32_risab_rif_conf *subr_cfg;
	struct io_pa_va base;
	unsigned int conf_lock;
	char risab_name[RISAB_NAME_LEN_MAX];
	uint32_t pages_configured;
	bool srwiad;

	SLIST_ENTRY(stm32_risab_pdata) link;
};

static SLIST_HEAD(, stm32_risab_pdata) risab_list =
		SLIST_HEAD_INITIALIZER(risab_list);

static bool is_tdcid;

static vaddr_t risab_base(struct stm32_risab_pdata *risab)
{
	return io_pa_or_va_secure(&risab->base, 1);
}

void stm32_risab_clear_illegal_access_flags(void)
{
	struct stm32_risab_pdata *risab = NULL;

	SLIST_FOREACH(risab, &risab_list, link) {
		vaddr_t base = risab_base(risab);

		if (!io_read32(base + _RISAB_IASR))
			continue;

		io_write32(base + _RISAB_IACR, _RISAB_IACR_CAEF |
			   _RISAB_IACR_IAEF);
	}
}

#ifdef CFG_TEE_CORE_DEBUG
void stm32_risab_print_erroneous_data(void)
{
	struct stm32_risab_pdata *risab = NULL;

	SLIST_FOREACH(risab, &risab_list, link) {
		vaddr_t base = risab_base(risab);

		/* Check if faulty address on this RISAB */
		if (!io_read32(base + _RISAB_IASR))
			continue;

		EMSG("\n\nDUMPING DATA FOR %s\n\n", risab->risab_name);
		EMSG("=====================================================");
		EMSG("Status register (IAESR): %#"PRIx32,
		     io_read32(base + _RISAB_IAESR));
		EMSG("-----------------------------------------------------");
		EMSG("Faulty address (IADDR): %#"PRIx32,
		     io_read32(base + _RISAB_IADDR));
		EMSG("=====================================================\n");
	};
}
#endif /* CFG_TEE_CORE_DEBUG */

static bool regs_access_granted(struct stm32_risab_pdata *risab_d,
				unsigned int reg_idx)
{
	unsigned int first_page = risab_d->subr_cfg[reg_idx].first_page;
	uint32_t cidcfgr = io_read32(risab_base(risab_d) +
				     _RISAB_PGy_CIDCFGR(first_page));

	/* Trusted CID access */
	if (is_tdcid &&
	    ((cidcfgr & _RISAB_PG_CIDCFGR_CFEN &&
	      !(cidcfgr & _RISAB_PG_CIDCFGR_DCEN)) ||
	     !(cidcfgr & _RISAB_PG_CIDCFGR_CFEN)))
		return true;

	/* Delegated CID access check */
	if (cidcfgr & _RISAB_PG_CIDCFGR_CFEN &&
	    cidcfgr & _RISAB_PG_CIDCFGR_DCEN &&
	    ((cidcfgr & _RISAB_PG_CIDCFGR_DDCID_MASK) >>
	     _RISAB_PG_CIDCFGR_DDCID_SHIFT) == RIF_CID1)
		return true;

	return false;
}

static void set_block_seccfgr(struct stm32_risab_pdata *risab_d,
			      struct stm32_risab_rif_conf *subr_cfg)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;
	unsigned int last_page = subr_cfg->first_page +
				 subr_cfg->nb_pages_cfged - 1;

	for (i = subr_cfg->first_page; i <= last_page; i++)
		io_clrsetbits32(base + _RISAB_PGy_SECCFGR(i),
				_RISAB_PG_SECCFGR_MASK, subr_cfg->seccfgr);
}

static void set_block_dprivcfgr(struct stm32_risab_pdata *risab_d,
				struct stm32_risab_rif_conf *subr_cfg)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;
	unsigned int last_page = subr_cfg->first_page +
				 subr_cfg->nb_pages_cfged - 1;

	for (i = subr_cfg->first_page; i <= last_page; i++)
		io_clrsetbits32(base + _RISAB_PGy_PRIVCFGR(i),
				_RISAB_PG_PRIVCFGR_MASK,
				subr_cfg->dprivcfgr);
}

static void set_cidcfgr(struct stm32_risab_pdata *risab_d,
			struct stm32_risab_rif_conf *subr_cfg)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;
	unsigned int last_page = subr_cfg->first_page +
				 subr_cfg->nb_pages_cfged - 1;

	for (i = subr_cfg->first_page; i <= last_page; i++) {
		/*
		 * When TDCID, OP-TEE should be the one to set the CID filtering
		 * configuration. Clearing previous configuration prevents
		 * undesired events during the only legitimate configuration.
		 */
		io_clrsetbits32(base + _RISAB_PGy_CIDCFGR(i),
				_RISAB_PG_CIDCFGR_CONF_MASK,
				subr_cfg->cidcfgr);
	}
}

static void set_read_conf(struct stm32_risab_pdata *risab_d,
			  struct stm32_risab_rif_conf *subr_cfg)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;
	unsigned int last_page = subr_cfg->first_page +
				 subr_cfg->nb_pages_cfged - 1;
	uint32_t mask = GENMASK_32(last_page, subr_cfg->first_page);

	for (i = 0; i < _RISAB_NB_MAX_CID_SUPPORTED; i++) {
		if (subr_cfg->rlist[i])
			io_setbits32(base + _RISAB_CIDxRDCFGR(i), mask);
	}
}

static void set_write_conf(struct stm32_risab_pdata *risab_d,
			   struct stm32_risab_rif_conf *subr_cfg)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;
	unsigned int last_page = subr_cfg->first_page +
				 subr_cfg->nb_pages_cfged - 1;
	uint32_t mask = GENMASK_32(last_page, subr_cfg->first_page);

	for (i = 0; i < _RISAB_NB_MAX_CID_SUPPORTED; i++) {
		if (subr_cfg->wlist[i])
			io_setbits32(base + _RISAB_CIDxWRCFGR(i), mask);
	}
}

static void set_cid_priv_conf(struct stm32_risab_pdata *risab_d,
			      struct stm32_risab_rif_conf *subr_cfg)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;
	unsigned int last_page = subr_cfg->first_page +
				 subr_cfg->nb_pages_cfged - 1;
	uint32_t mask = GENMASK_32(last_page, subr_cfg->first_page);

	for (i = 0; i < _RISAB_NB_MAX_CID_SUPPORTED; i++) {
		if (subr_cfg->plist[i])
			io_clrsetbits32(base + _RISAB_CIDxPRIVCFGR(i), mask,
					subr_cfg->plist[i]);
	}
}

static void apply_rif_config(struct stm32_risab_pdata *risab_d)
{
	vaddr_t base = risab_base(risab_d);
	unsigned int i = 0;

	/* If TDCID, we expect to restore default RISAB configuration */
	if (is_tdcid) {
		for (i = 0; i < _RISAB_NB_PAGES_MAX; i++) {
			io_clrbits32(base + _RISAB_PGy_CIDCFGR(i),
				     _RISAB_PG_CIDCFGR_CONF_MASK);
			io_clrbits32(base + _RISAB_PGy_SECCFGR(i),
				     _RISAB_PG_SECCFGR_MASK);
			io_clrbits32(base + _RISAB_PGy_PRIVCFGR(i),
				     _RISAB_PG_PRIVCFGR_MASK);
		}
		for (i = 0; i < _RISAB_NB_MAX_CID_SUPPORTED; i++) {
			io_clrbits32(base + _RISAB_CIDxRDCFGR(i), UINT32_MAX);
			io_clrbits32(base + _RISAB_CIDxWRCFGR(i), UINT32_MAX);
			io_clrbits32(base + _RISAB_CIDxPRIVCFGR(i), UINT32_MAX);
		}
	}

	for (i = 0; i < risab_d->nb_regions_cfged; i++) {
		set_block_dprivcfgr(risab_d, &risab_d->subr_cfg[i]);

		/* Only cortex A35 running OP-TEE can access RISAB1/2 */
		if (virt_to_phys((void *)base) != RISAB1_BASE &&
		    virt_to_phys((void *)base) != RISAB2_BASE) {
			/* Delegate RIF configuration or not */
			if (!is_tdcid)
				DMSG("Cannot set %s CID config for region %u",
				     risab_d->risab_name, i);
			else
				set_cidcfgr(risab_d, &risab_d->subr_cfg[i]);

			if (!regs_access_granted(risab_d, i))
				panic();
		} else {
			set_cidcfgr(risab_d, &risab_d->subr_cfg[i]);
		}

		/*
		 * This sequence will generate an IAC if the CID filtering
		 * configuration is inconsistent with these desired rights
		 * to apply. Start by default setting security configuration
		 * for all blocks.
		 */
		set_block_seccfgr(risab_d, &risab_d->subr_cfg[i]);

		/* Grant page access to some CIDs, in read and/or write */
		set_read_conf(risab_d, &risab_d->subr_cfg[i]);
		set_write_conf(risab_d, &risab_d->subr_cfg[i]);

		/* For each granted CID define privilege access per page */
		set_cid_priv_conf(risab_d, &risab_d->subr_cfg[i]);
	}
}

static void parse_risab_rif_conf(struct stm32_risab_pdata *risab_d,
				 struct stm32_risab_rif_conf *subr_cfg,
				 uint32_t rif_conf, bool check_overlap)
{
	unsigned int first_page = subr_cfg->first_page;
	unsigned int last_page = first_page + subr_cfg->nb_pages_cfged - 1;
	uint32_t reg_pages_cfged = GENMASK_32(last_page, first_page);
	unsigned int i = 0;

	assert(last_page <= _RISAB_NB_PAGES_MAX);

	DMSG("Configuring pages %u to %u", first_page, last_page);

	/* Parse secure configuration */
	if (rif_conf & BIT(RISAB_SEC_SHIFT)) {
		subr_cfg->seccfgr = _RISAB_PG_SECCFGR_MASK;
		/*
		 * Memory region overlapping should only be checked at platform
		 * setup when memory mapping is first applied. A region's
		 * attributes can later be dynamically modified but not its
		 * bounds.
		 */
		if (check_overlap &&
		    reg_pages_cfged & risab_d->pages_configured)
			panic("Memory region overlap detected");
	} else {
		subr_cfg->seccfgr = 0;
	}

	/* Parse default privilege configuration */
	if (rif_conf & BIT(RISAB_DPRIV_SHIFT)) {
		subr_cfg->dprivcfgr = _RISAB_PG_PRIVCFGR_MASK;
		if (check_overlap &&
		    reg_pages_cfged & risab_d->pages_configured)
			panic("Memory region overlap detected");
	} else {
		subr_cfg->dprivcfgr = 0;
	}

	if (check_overlap)
		risab_d->pages_configured |= reg_pages_cfged;

	for (i = 0; i < _RISAB_NB_MAX_CID_SUPPORTED; i++) {
		/* RISAB compartment priv configuration */
		if (rif_conf & BIT(i))
			subr_cfg->plist[i] |= GENMASK_32(last_page, first_page);

		/* RISAB compartment read configuration */
		if (rif_conf & BIT(i + RISAB_READ_LIST_SHIFT))
			subr_cfg->rlist[i] |= GENMASK_32(last_page, first_page);

		/* RISAB compartment write configuration */
		if (rif_conf & BIT(i + RISAB_WRITE_LIST_SHIFT))
			subr_cfg->wlist[i] |= GENMASK_32(last_page, first_page);
	}

	/* CID filtering configuration */
	if (rif_conf & BIT(RISAB_CFEN_SHIFT))
		subr_cfg->cidcfgr |= _RISAB_PG_CIDCFGR_CFEN;

	if (rif_conf & BIT(RISAB_DCEN_SHIFT))
		subr_cfg->cidcfgr |= _RISAB_PG_CIDCFGR_DCEN;

	if (rif_conf & RISAB_DCCID_MASK) {
		uint32_t ddcid = SHIFT_U32((rif_conf & RISAB_DCCID_MASK) >>
					   RISAB_DCCID_SHIFT,
					   _RISAB_PG_CIDCFGR_DDCID_SHIFT);

		assert(((rif_conf & RISAB_DCCID_MASK) >> RISAB_DCCID_SHIFT) <
		       _RISAB_NB_MAX_CID_SUPPORTED);

		subr_cfg->cidcfgr |= ddcid;
	}
}

static TEE_Result parse_dt(const void *fdt, int node,
			   struct stm32_risab_pdata *risab_d)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *mem_regions = NULL;
	struct dt_node_info info = { };
	const fdt32_t *cuint = NULL;
	int mem_reg_node = 0;
	unsigned int i = 0;
	int lenp = 0;

	fdt_fill_device_info(fdt, &info, node);
	assert(info.reg != DT_INFO_INVALID_REG &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	risab_d->base.pa = info.reg;

	/* Gate the IP */
	res = clk_dt_get_by_index(fdt, node, 0, &risab_d->clock);
	if (res)
		return res;

	strlcpy(risab_d->risab_name, fdt_get_name(fdt, node, NULL),
		sizeof(risab_d->risab_name));

	cuint = fdt_getprop(fdt, node, "st,srwiad", NULL);
	if (cuint)
		risab_d->srwiad = true;

	/* Get the memory region being configured */
	cuint = fdt_getprop(fdt, node, "st,mem-map", &lenp);
	if (!cuint)
		panic("Missing st,mem-map property in configure memory region");

	assert((unsigned int)(lenp / sizeof(uint32_t)) == 2);

	risab_d->region_cfged.base = fdt32_to_cpu(cuint[0]);
	risab_d->region_cfged.size = fdt32_to_cpu(cuint[1]);

	/* Get the memory regions to configure */
	mem_regions = fdt_getprop(fdt, node, "memory-region", &lenp);
	if (!mem_regions)
		panic("No memory region to configure");

	risab_d->nb_regions_cfged = (unsigned int)(lenp / sizeof(uint32_t));
	assert(risab_d->nb_regions_cfged < _RISAB_NB_PAGES_MAX);

	risab_d->subr_cfg = calloc(risab_d->nb_regions_cfged,
				   sizeof(*risab_d->subr_cfg));
	if (!risab_d->subr_cfg)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < risab_d->nb_regions_cfged; i++) {
		uint32_t phandle = fdt32_to_cpu(mem_regions[i]);
		size_t sub_region_offset = 0;
		paddr_t address = 0;
		size_t length = 0;

		mem_reg_node = fdt_node_offset_by_phandle(fdt, phandle);
		if (mem_reg_node < 0)
			return TEE_ERROR_ITEM_NOT_FOUND;

		/*
		 * Get the reg property to determine the number of pages
		 * to configure
		 */
		address = fdt_reg_base_address(fdt, mem_reg_node);
		length = fdt_reg_size(fdt, mem_reg_node);

		assert(IS_ALIGNED(address, _RISAB_PAGE_SIZE) &&
		       IS_ALIGNED(length, _RISAB_PAGE_SIZE));

		/*
		 * Get the sub region offset and check if it is not out
		 * of bonds
		 */
		sub_region_offset = address - risab_d->region_cfged.base;

		if (!core_is_buffer_inside(address, length,
					   risab_d->region_cfged.base,
					   risab_d->region_cfged.size)) {
			EMSG("Region %#"PRIxPA"..%#"PRIxPA" outside RISAB area %#"PRIxPA"...%#"PRIxPA,
			     address, address + length,
			     risab_d->region_cfged.base,
			     risab_d->region_cfged.base +
			     risab_d->region_cfged.size);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		risab_d->subr_cfg[i].first_page = sub_region_offset /
						  _RISAB_PAGE_SIZE;
		risab_d->subr_cfg[i].nb_pages_cfged = length /
						      _RISAB_PAGE_SIZE;
		if (!risab_d->subr_cfg[i].nb_pages_cfged)
			panic("Range to configure is < to the size of a page");

		/* Get the RIF configuration for this region */
		cuint = fdt_getprop(fdt, mem_reg_node, "st,protreg", &lenp);
		if (!cuint)
			panic("No RIF configuration available");

		/* There should be only one configuration for this region */
		assert((unsigned int)(lenp / sizeof(uint32_t)) == 1);

		parse_risab_rif_conf(risab_d, &risab_d->subr_cfg[i],
				     fdt32_to_cpu(cuint[0]),
				     true /*check_overlap*/);
	}

	return TEE_SUCCESS;
}

static void enable_srwiad_if_set(struct stm32_risab_pdata *risab_d)
{
	if (is_tdcid && risab_d->srwiad)
		io_setbits32(risab_base(risab_d), _RISAB_CR_SRWIAD);
};

static void disable_srwiad_if_unset(struct stm32_risab_pdata *risab_d)
{
	if (is_tdcid && !risab_d->srwiad)
		io_clrbits32(risab_base(risab_d), _RISAB_CR_SRWIAD);
};

static void clear_iac_regs(struct stm32_risab_pdata *risab_d)
{
	io_setbits32(risab_base(risab_d) + _RISAB_IACR, _RISAB_IACR_MASK);
}

static void set_vderam_syscfg(struct stm32_risab_pdata *risab_d)
{
	/*
	 * Set the VDERAMCR_VDERAM_EN bit if the VDERAM should be accessed by
	 * the system. Else, clear it so that VDEC/VENC can access it.
	 */
	if (risab_d->nb_regions_cfged)
		stm32mp_syscfg_write(SYSCFG_VDERAMCR, VDERAMCR_VDERAM_EN,
				     VDERAMCR_MASK);
	else
		stm32mp_syscfg_write(SYSCFG_VDERAMCR, 0, VDERAMCR_MASK);
}

static struct stm32_risab_rif_conf *
get_subreg_by_range(struct stm32_risab_pdata *risab, paddr_t paddr, size_t size)
{
	unsigned int nb_page = size / _RISAB_PAGE_SIZE;
	unsigned int i = 0;

	for (i = 0; i < risab->nb_regions_cfged; i++) {
		unsigned int first_page = (paddr - risab->region_cfged.base) /
					  _RISAB_PAGE_SIZE;

		if (first_page == risab->subr_cfg[i].first_page &&
		    nb_page == risab->subr_cfg[i].nb_pages_cfged)
			return risab->subr_cfg + i;
	}

	return NULL;
}

static TEE_Result stm32_risab_check_access(struct firewall_query *fw,
					   paddr_t paddr, size_t size,
					   bool read, bool write)
{
	struct stm32_risab_rif_conf *reg_conf = NULL;
	struct stm32_risab_pdata *risab = NULL;
	unsigned int first_page = 0;
	uint32_t write_cids = 0;
	uint32_t read_cids = 0;
	uint32_t priv_cids = 0;
	uint32_t dprivcfgr = 0;
	uint32_t seccfgr = 0;
	uint32_t cidcfgr = 0;
	uint32_t q_conf = 0;
	unsigned int i = 0;
	vaddr_t base = 0;

	assert(fw->ctrl->priv && (read || write));

	risab = fw->ctrl->priv;
	base = risab_base(risab);

	if (!IS_ALIGNED(paddr, _RISAB_PAGE_SIZE) ||
	    !IS_ALIGNED(size, _RISAB_PAGE_SIZE)) {
		EMSG("Physical address %"PRIxPA" or size:%#zx misaligned with RISAB page boundaries",
		     paddr, size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (fw->arg_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * RISAF region configuration, we assume the query is as
	 * follows:
	 * fw->args[0]: Configuration of the region
	 */
	q_conf = fw->args[0];

	reg_conf = get_subreg_by_range(risab, paddr, size);
	if (!reg_conf)
		return TEE_ERROR_BAD_PARAMETERS;

	first_page = reg_conf->first_page;

	seccfgr = io_read32(base + _RISAB_PGy_SECCFGR(first_page));
	/* Security level is exclusive on memories */
	if (!!(q_conf & BIT(RISAB_SEC_SHIFT)) ^ !!(seccfgr & BIT(first_page))) {
		if (!(q_conf & BIT(RISAB_SEC_SHIFT) &&
		      (io_read32(base + _RISAB_CR) & _RISAB_CR_SRWIAD)))
			return TEE_ERROR_ACCESS_DENIED;
	}

	dprivcfgr = io_read32(base + _RISAB_PGy_PRIVCFGR(first_page));
	cidcfgr = io_read32(base + _RISAB_PGy_CIDCFGR(first_page));

	if (!(cidcfgr & _RISAB_PG_CIDCFGR_CFEN)) {
		if (dprivcfgr && !(q_conf & BIT(RISAB_DPRIV_SHIFT)))
			return TEE_ERROR_ACCESS_DENIED;
		else
			return TEE_SUCCESS;
	}

	read_cids = SHIFT_U32(q_conf & RISAB_RLIST_MASK, RISAB_READ_LIST_SHIFT);
	write_cids = SHIFT_U32(q_conf & RISAB_WLIST_MASK,
			       RISAB_WRITE_LIST_SHIFT);
	priv_cids = q_conf & RISAB_PLIST_MASK;

	for (i = 0; i < _RISAB_NB_MAX_CID_SUPPORTED; i++) {
		uint32_t read_list = io_read32(base + _RISAB_CIDxRDCFGR(i));
		uint32_t write_list = io_read32(base + _RISAB_CIDxWRCFGR(i));
		uint32_t priv_list = io_read32(base + _RISAB_CIDxPRIVCFGR(i));

		if (read && (read_cids & BIT(i)) &&
		    !(read_list & BIT(first_page)))
			return TEE_ERROR_ACCESS_DENIED;

		if (write && (write_cids & BIT(i)) &&
		    !(write_list & BIT(first_page)))
			return TEE_ERROR_ACCESS_DENIED;

		if ((priv_list & BIT(first_page)) && !(priv_cids & BIT(i)))
			return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_risab_pm_resume(struct stm32_risab_pdata *risab)
{
	unsigned int i = 0;

	if (risab->base.pa == RISAB6_BASE)
		set_vderam_syscfg(risab);
	enable_srwiad_if_set(risab);
	clear_iac_regs(risab);

	for (i = 0; i < risab->nb_regions_cfged; i++) {
		/* Restoring RISAB RIF configuration */
		set_block_dprivcfgr(risab, &risab->subr_cfg[i]);

		if (!is_tdcid)
			DMSG("Cannot set %s CID configuration for region %u",
			     risab->risab_name, i);
		else
			set_cidcfgr(risab, &risab->subr_cfg[i]);

		if (!regs_access_granted(risab, i))
			continue;

		/*
		 * This sequence will generate an IAC if the CID filtering
		 * configuration is inconsistent with these desired rights
		 * to apply.
		 */
		set_block_seccfgr(risab, &risab->subr_cfg[i]);
		set_read_conf(risab, &risab->subr_cfg[i]);
		set_write_conf(risab, &risab->subr_cfg[i]);
		set_cid_priv_conf(risab, &risab->subr_cfg[i]);
	}

	disable_srwiad_if_unset(risab);

	return TEE_SUCCESS;
}

static TEE_Result stm32_risab_pm_suspend(struct stm32_risab_pdata *risab)
{
	vaddr_t base = risab_base(risab);
	size_t i = 0;

	for (i = 0; i < risab->nb_regions_cfged; i++) {
		size_t j = 0;
		unsigned int first_page = risab->subr_cfg[i].first_page;

		/* Save all configuration fields that need to be restored */
		risab->subr_cfg[i].seccfgr =
			io_read32(base + _RISAB_PGy_SECCFGR(first_page));
		risab->subr_cfg[i].dprivcfgr =
			io_read32(base + _RISAB_PGy_PRIVCFGR(first_page));
		risab->subr_cfg[i].cidcfgr =
			io_read32(base + _RISAB_PGy_CIDCFGR(first_page));

		for (j = 0; j < _RISAB_NB_MAX_CID_SUPPORTED; j++) {
			risab->subr_cfg[i].rlist[j] =
				io_read32(base + _RISAB_CIDxRDCFGR(j));
			risab->subr_cfg[i].wlist[j] =
				io_read32(base + _RISAB_CIDxWRCFGR(j));
			risab->subr_cfg[i].plist[j] =
				io_read32(base + _RISAB_CIDxPRIVCFGR(j));
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32_risab_pm(enum pm_op op, unsigned int pm_hint,
	       const struct pm_callback_handle *pm_handle)
{
	struct stm32_risab_pdata *risab = pm_handle->handle;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT) || !is_tdcid)
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME)
		res = stm32_risab_pm_resume(risab);
	else
		res = stm32_risab_pm_suspend(risab);

	return res;
}

static const struct firewall_controller_ops firewall_ops = {
	.check_memory_access = stm32_risab_check_access,
};

static TEE_Result stm32_risab_probe(const void *fdt, int node,
				    const void *compat_data __maybe_unused)
{
	struct firewall_controller *controller = NULL;
	struct stm32_risab_pdata *risab_d = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	risab_d = calloc(1, sizeof(*risab_d));
	if (!risab_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = parse_dt(fdt, node, risab_d);
	if (res)
		goto err;

	if (clk_enable(risab_d->clock))
		panic("Can't enable RISAB clock");

	if (is_tdcid) {
		if (risab_d->base.pa == RISAB6_BASE)
			set_vderam_syscfg(risab_d);
		clear_iac_regs(risab_d);
		enable_srwiad_if_set(risab_d);
	}

	apply_rif_config(risab_d);

	disable_srwiad_if_unset(risab_d);

	controller = calloc(1, sizeof(*controller));
	if (!controller) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	controller->base = &risab_d->base;
	controller->name = risab_d->risab_name;
	controller->priv = risab_d;
	controller->ops = &firewall_ops;

	SLIST_INSERT_HEAD(&risab_list, risab_d, link);

	res = firewall_dt_controller_register(fdt, node, controller);
	if (res)
		panic();

	register_pm_core_service_cb(stm32_risab_pm, risab_d, "stm32-risab");

	return TEE_SUCCESS;

err:
	clk_disable(risab_d->clock);
	free(risab_d->subr_cfg);
	free(risab_d);

	return res;
}

static const struct dt_device_match risab_match_table[] = {
	{ .compatible = "st,stm32mp25-risab" },
	{ }
};

DEFINE_DT_DRIVER(risab_dt_driver) = {
	.name = "stm32-risab",
	.match_table = risab_match_table,
	.probe = stm32_risab_probe,
};
