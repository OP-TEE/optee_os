// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, STMicroelectronics
 */

#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_rif.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>

/* STM32 Registers */
#define _TAMP_CR1			0x00U
#define _TAMP_CR2			0x04U
#define _TAMP_CR3			0x08U
#define _TAMP_FLTCR			0x0CU
#define _TAMP_ATCR1			0x10U
#define _TAMP_ATSEEDR			0x14U
#define _TAMP_ATOR			0x18U
#define _TAMP_ATCR2			0x1CU
#define _TAMP_SECCFGR			0x20U
#define _TAMP_SMCR			0x20U
#define _TAMP_PRIVCFGR			0x24U
#define _TAMP_IER			0x2CU
#define _TAMP_SR			0x30U
#define _TAMP_MISR			0x34U
#define _TAMP_SMISR			0x38U
#define _TAMP_SCR			0x3CU
#define _TAMP_COUNTR			0x40U
#define _TAMP_COUNT2R			0x44U
#define _TAMP_OR			0x50U
#define _TAMP_ERCFGR			0X54U
#define _TAMP_BKPRIFR(x)		(0x70U + 0x4U * ((x) - 1U))
#define _TAMP_CIDCFGR(x)		(0x80U + 0x4U * (x))
#define _TAMP_BKPxR(x)			(0x100U + 0x4U * ((x) - 1U))
#define _TAMP_HWCFGR2			0x3ECU
#define _TAMP_HWCFGR1			0x3F0U
#define _TAMP_VERR			0x3F4U
#define _TAMP_IPIDR			0x3F8U
#define _TAMP_SIDR			0x3FCU

/* _TAMP_SECCFGR bit fields */
#define _TAMP_SECCFGR_BKPRWSEC_MASK	GENMASK_32(7, 0)
#define _TAMP_SECCFGR_BKPRWSEC_SHIFT	0U
#define _TAMP_SECCFGR_CNT2SEC		BIT(14)
#define _TAMP_SECCFGR_CNT2SEC_SHIFT	14U
#define _TAMP_SECCFGR_CNT1SEC		BIT(15)
#define _TAMP_SECCFGR_CNT1SEC_SHIFT	15U
#define _TAMP_SECCFGR_BKPWSEC_MASK	GENMASK_32(23, 16)
#define _TAMP_SECCFGR_BKPWSEC_SHIFT	16U
#define _TAMP_SECCFGR_BHKLOCK		BIT(30)
#define _TAMP_SECCFGR_TAMPSEC		BIT(31)
#define _TAMP_SECCFGR_TAMPSEC_SHIFT	31U
#define _TAMP_SECCFGR_BUT_BKP_MASK	(GENMASK_32(31, 30) | \
					 GENMASK_32(15, 14))
#define _TAMP_SECCFGR_RIF_TAMP_SEC	BIT(0)
#define _TAMP_SECCFGR_RIF_COUNT_1	BIT(1)
#define _TAMP_SECCFGR_RIF_COUNT_2	BIT(2)

/* _TAMP_SMCR bit fields */
#define _TAMP_SMCR_BKPRWDPROT_MASK	GENMASK_32(7, 0)
#define _TAMP_SMCR_BKPRWDPROT_SHIFT	0U
#define _TAMP_SMCR_BKPWDPROT_MASK	GENMASK_32(23, 16)
#define _TAMP_SMCR_BKPWDPROT_SHIFT	16U
#define _TAMP_SMCR_DPROT		BIT(31)
/*
 * _TAMP_PRIVCFGR bit fields
 */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))
#define _TAMP_PRIVCFGR_RIF_TAMP_PRIV	BIT(0)
#define _TAMP_PRIVCFGR_RIF_R1		BIT(1)
#define _TAMP_PRIVCFGR_RIF_R2		BIT(2)

/*
 * _TAMP_PRIVCFGR bit fields
 */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))

/* _TAMP_HWCFGR2 bit fields */
#define _TAMP_HWCFGR2_TZ		GENMASK_32(11, 8)
#define _TAMP_HWCFGR2_OR		GENMASK_32(7, 0)

/* _TAMP_HWCFGR1 bit fields */
#define _TAMP_HWCFGR1_BKPREG		GENMASK_32(7, 0)
#define _TAMP_HWCFGR1_TAMPER		GENMASK_32(11, 8)
#define _TAMP_HWCFGR1_ACTIVE		GENMASK_32(15, 12)
#define _TAMP_HWCFGR1_INTERN		GENMASK_32(31, 16)
#define _TAMP_HWCFGR1_ITAMP_MAX_ID	16U
#define _TAMP_HWCFGR1_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)

/* _TAMP_VERR bit fields */
#define _TAMP_VERR_MINREV		GENMASK_32(3, 0)
#define _TAMP_VERR_MAJREV		GENMASK_32(7, 4)

/*
 * CIDCFGR register bitfields
 */
#define _TAMP_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define _TAMP_CIDCFGR_CONF_MASK		(_CIDCFGR_CFEN |	 \
					 _CIDCFGR_SEMEN |	 \
					 _TAMP_CIDCFGR_SCID_MASK)

/* _TAMP_BKPRIFR */
#define _TAMP_BKPRIFR_1_MASK		GENMASK_32(7, 0)
#define _TAMP_BKPRIFR_2_MASK		GENMASK_32(7, 0)
#define _TAMP_BKPRIFR_3_MASK		(GENMASK_32(23, 16) | GENMASK_32(7, 0))
#define _TAMP_BKPRIFR_ZONE3_RIF2_SHIFT	16U

/*
 * RIF miscellaneous
 */
#define TAMP_NB_BKPR_ZONES		3U
#define TAMP_RIF_RESOURCES		3U
#define TAMP_RIF_OFFSET_CNT		4U

/*
 * Compatibility capabilities
 * TAMP_HAS_REGISTER_SECCFGR - Supports SECCFGR, otherwise supports SMCR
 * register
 * TAMP_HAS_REGISTER_PRIVCFG - Supports PRIVCFGR configuration register
 * TAMP_HAS_RIF_SUPPORT - Supports RIF
 */
#define TAMP_HAS_REGISTER_SECCFGR	BIT(0)
#define TAMP_HAS_REGISTER_PRIVCFGR	BIT(1)
#define TAMP_HAS_RIF_SUPPORT		BIT(31)

/**
 * struct stm32_tamp_compat - TAMP compatible data
 * @nb_monotonic_counter: Number of monotic counter supported
 * @tags: Bit flags TAMP_HAS_* for compatibility management
 */
struct stm32_tamp_compat {
	int nb_monotonic_counter;
	uint32_t tags;
};

/*
 * struct stm32_bkpregs_conf - Backup registers zone bounds
 * @zone1_end - Number of backup registers in zone 1
 * @zone2_end - Number of backup registers in zone 2 + zone 1
 * @rif_offsets - RIF offsets used for CID compartments
 *
 * TAMP backup registers access permissions
 *
 * Zone 1: read/write in secure state, no access in non-secure state
 * Zone 2: read/write in secure state, read-only in non-secure state
 * Zone 3: read/write in secure state, read/write in non-secure state
 *
 * Protection zone 1
 * If zone1_end == 0 no backup register are in zone 1.
 * Otherwise backup registers from TAMP_BKP0R to TAMP_BKP<x>R are in zone 1,
 * with <x> = (@zone1_end - 1).
 *
 * Protection zone 2
 * If zone2_end == 0 no backup register are in zone 2 and zone 1.
 * Otherwise backup registers from TAMP_BKP<y>R to TAMP_BKP<z>R are in zone 2,
 * with <y> = @zone1_end and <z> = (@zone2_end - 1).
 *
 * Protection zone 3
 * Backup registers from TAMP_BKP<t>R to last backup register are in zone 3,
 * with <t> = (@zone2_end - 1).
 *
 * When RIF is supported, each zone can be subdivided to restrain accesses to
 * some CIDs.
 */
struct stm32_bkpregs_conf {
	uint32_t zone1_end;
	uint32_t zone2_end;
	uint32_t *rif_offsets;
};

/**
 * struct stm32_tamp_platdata - TAMP platform data
 * @base: IOMEM base address
 * @bkpregs_conf: TAMP backup register configuration reference
 * @compat: Reference to compat data passed at driver initialization
 * @conf_data: RIF configuration data
 * @clock: TAMP clock
 * @nb_rif_resources: Number of RIF resources
 * @it: TAMP interrupt number
 * @is_tdcid: True if current processor is TDCID
 */
struct stm32_tamp_platdata {
	struct io_pa_va base;
	struct stm32_bkpregs_conf bkpregs_conf;
	struct stm32_tamp_compat *compat;
	struct rif_conf_data *conf_data;
	struct clk *clock;
	unsigned int nb_rif_resources;
	int it;
	bool is_tdcid;
};

/**
 * struct stm32_tamp_instance - TAMP instance data
 * @pdata: TAMP platform data
 * @hwconf1: Copy of TAMP HWCONF1 register content
 * @hwconf2: Copy of TAMP HWCONF2 register content
 */
struct stm32_tamp_instance {
	struct stm32_tamp_platdata pdata;
	uint32_t hwconf1;
	uint32_t hwconf2;
};

/* Expects at most a single instance */
static struct stm32_tamp_instance *stm32_tamp_dev;

static void apply_rif_config(void)
{
	struct rif_conf_data *rif_conf = stm32_tamp_dev->pdata.conf_data;
	vaddr_t base = io_pa_or_va(&stm32_tamp_dev->pdata.base, 1);
	uint32_t access_mask_priv_reg = 0;
	uint32_t access_mask_sec_reg = 0;
	uint32_t privcfgr = 0;
	uint32_t seccfgr = 0;
	unsigned int i = 0;

	if (!stm32_tamp_dev->pdata.conf_data)
		return;

	/* Build access masks for _TAMP_PRIVCFGR and _TAMP_SECCFGR */
	for (i = 0; i < TAMP_RIF_RESOURCES; i++) {
		if (BIT(i) & rif_conf->access_mask[0]) {
			switch (i) {
			case 0:
				access_mask_sec_reg |= _TAMP_SECCFGR_TAMPSEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_TAMPPRIV;
				break;
			case 1:
				access_mask_sec_reg |= _TAMP_SECCFGR_CNT1SEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_CNT1PRIV;
				access_mask_priv_reg |= _TAMP_PRIVCFG_BKPRWPRIV;
				break;
			case 2:
				access_mask_sec_reg |= _TAMP_SECCFGR_CNT2SEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_CNT2PRIV;
				access_mask_priv_reg |= _TAMP_PRIVCFG_BKPWPRIV;
				break;
			default:
				panic();
			}
		}
	}

	/*
	 * When TDCID, OP-TEE should be the one to set the CID filtering
	 * configuration. Clearing previous configuration prevents
	 * undesired events during the only legitimate configuration.
	 */
	if (stm32_tamp_dev->pdata.is_tdcid) {
		for (i = 0; i < TAMP_RIF_RESOURCES; i++)
			if (BIT(i) & rif_conf->access_mask[0])
				io_clrbits32(base + _TAMP_CIDCFGR(i),
					     _TAMP_CIDCFGR_CONF_MASK);
	}

	if (rif_conf->sec_conf[0] & _TAMP_SECCFGR_RIF_TAMP_SEC)
		seccfgr |= _TAMP_SECCFGR_TAMPSEC;
	if (rif_conf->sec_conf[0] & _TAMP_SECCFGR_RIF_COUNT_1)
		seccfgr |= _TAMP_SECCFGR_CNT1SEC;
	if (rif_conf->sec_conf[0] & _TAMP_SECCFGR_RIF_COUNT_2)
		seccfgr |= _TAMP_SECCFGR_CNT2SEC;

	if (rif_conf->priv_conf[0] & _TAMP_PRIVCFGR_RIF_TAMP_PRIV)
		privcfgr |= _TAMP_PRIVCFG_TAMPPRIV;
	if (rif_conf->priv_conf[0] & _TAMP_PRIVCFGR_RIF_R1)
		privcfgr |= _TAMP_PRIVCFG_CNT1PRIV | _TAMP_PRIVCFG_BKPRWPRIV;
	if (rif_conf->priv_conf[0] & _TAMP_PRIVCFGR_RIF_R2)
		privcfgr |= _TAMP_PRIVCFG_CNT2PRIV | _TAMP_PRIVCFG_BKPWPRIV;

	/* Security and privilege RIF configuration */
	io_clrsetbits32(base + _TAMP_PRIVCFGR, access_mask_priv_reg, privcfgr);
	io_clrsetbits32(base + _TAMP_SECCFGR, access_mask_sec_reg, seccfgr);

	if (!stm32_tamp_dev->pdata.is_tdcid)
		return;

	for (i = 0; i < TAMP_RIF_RESOURCES; i++) {
		if (!(BIT(i) & rif_conf->access_mask[0]))
			continue;

		io_clrsetbits32(base + _TAMP_CIDCFGR(i),
				_TAMP_CIDCFGR_CONF_MASK,
				rif_conf->cid_confs[i]);
	}
}

static TEE_Result stm32_tamp_apply_bkpr_rif_conf(void)
{
	struct stm32_bkpregs_conf *bkpregs_conf =
			&stm32_tamp_dev->pdata.bkpregs_conf;
	vaddr_t base = io_pa_or_va(&stm32_tamp_dev->pdata.base, 1);
	unsigned int i = 0;

	if (!bkpregs_conf->rif_offsets)
		panic("No backup register configuration");

	for (i = 0; i < TAMP_RIF_OFFSET_CNT; i++) {
		if (bkpregs_conf->rif_offsets[i] >
		    (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG))
			return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Fill the 3 TAMP_BKPRIFRx registers */
	io_clrsetbits32(base + _TAMP_BKPRIFR(1), _TAMP_BKPRIFR_1_MASK,
			bkpregs_conf->rif_offsets[0]);
	io_clrsetbits32(base + _TAMP_BKPRIFR(2), _TAMP_BKPRIFR_2_MASK,
			bkpregs_conf->rif_offsets[1]);
	io_clrsetbits32(base + _TAMP_BKPRIFR(3), _TAMP_BKPRIFR_3_MASK,
			bkpregs_conf->rif_offsets[2] |
			SHIFT_U32(bkpregs_conf->rif_offsets[3],
				  _TAMP_BKPRIFR_ZONE3_RIF2_SHIFT));

	DMSG("Backup registers mapping :");
	DMSG("********START of zone 1********");
	DMSG("Protection Zone 1-RIF1 begins at register: 0");
	DMSG("Protection Zone 1-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[0]);
	DMSG("Protection Zone 1-RIF2 ends at register: %"PRIu32,
	     bkpregs_conf->zone1_end ? bkpregs_conf->zone1_end - 1 : 0);
	DMSG("********END of zone 1********");
	DMSG("********START of zone 2********");
	DMSG("Protection Zone 2-RIF1 begins at register: %"PRIu32,
	     bkpregs_conf->zone1_end);
	DMSG("Protection Zone 2-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[1]);
	DMSG("Protection Zone 2-RIF2 ends at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[1] > bkpregs_conf->zone1_end ?
	     bkpregs_conf->zone2_end - 1 : 0);
	DMSG("********END of zone 2********");
	DMSG("********START of zone 3********");
	DMSG("Protection Zone 3-RIF1 begins at register: %"PRIu32,
	     bkpregs_conf->zone2_end);
	DMSG("Protection Zone 3-RIF0 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[2]);
	DMSG("Protection Zone 3-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[3]);
	DMSG("Protection Zone 3-RIF2 ends at the last register: %"PRIu32,
	     stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG);
	DMSG("********END of zone 3********");

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_set_secure_bkpregs(void)
{
	struct stm32_bkpregs_conf *bkpregs_conf =
		&stm32_tamp_dev->pdata.bkpregs_conf;
	vaddr_t base = 0;
	uint32_t first_z2 = 0;
	uint32_t first_z3 = 0;

	base = io_pa_or_va(&stm32_tamp_dev->pdata.base, 1);

	first_z2 = bkpregs_conf->zone1_end;
	first_z3 = bkpregs_conf->zone2_end;

	if ((first_z2 > (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG)) ||
	    (first_z3 > (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPRWSEC_MASK,
				(first_z2 << _TAMP_SECCFGR_BKPRWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPRWSEC_MASK);

		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPWSEC_MASK,
				(first_z3 << _TAMP_SECCFGR_BKPWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPWSEC_MASK);
	} else {
		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPRWDPROT_MASK,
				(first_z2 << _TAMP_SMCR_BKPRWDPROT_SHIFT) &
				_TAMP_SMCR_BKPRWDPROT_MASK);

		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPWDPROT_MASK,
				(first_z3 << _TAMP_SMCR_BKPWDPROT_SHIFT) &
				_TAMP_SMCR_BKPWDPROT_MASK);
	}

	return TEE_SUCCESS;
}

static void stm32_tamp_set_secure(uint32_t mode)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp_dev->pdata.base, 1);

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BUT_BKP_MASK,
				mode & _TAMP_SECCFGR_BUT_BKP_MASK);
	} else {
		/*
		 * Note: MP15 doesn't use SECCFG register and
		 * inverts the secure bit.
		 */
		if (mode & _TAMP_SECCFGR_TAMPSEC)
			io_clrbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
		else
			io_setbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
	}
}

static void stm32_tamp_set_privilege(uint32_t mode)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp_dev->pdata.base, 1);

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_PRIVCFGR))
		io_clrsetbits32(base + _TAMP_PRIVCFGR, _TAMP_PRIVCFGR_MASK,
				mode & _TAMP_PRIVCFGR_MASK);
}

static void parse_bkpregs_dt_conf(const void *fdt, int node)
{
	struct stm32_tamp_platdata *pdata = &stm32_tamp_dev->pdata;
	unsigned int bkpregs_count = 0;
	const fdt32_t *cuint = NULL;
	int lenp = 0;

	cuint = fdt_getprop(fdt, node, "st,backup-zones", &lenp);
	if (!cuint)
		panic("Missing backup registers configuration");

	/*
	 * When TAMP does not support RIF, the backup registers can
	 * be splited in 3 zones. These zones have specific read/write
	 * access permissions based on the secure status of the accesser.
	 * When RIF is supported, these zones can additionally be splited
	 * in subzones that have CID filtering. Zones/Subzones can be empty and
	 * are contiguous.
	 */
	if (!(pdata->compat->tags & TAMP_HAS_RIF_SUPPORT)) {
		/* 3 zones, 2 offsets to apply */
		if (lenp != sizeof(uint32_t) * TAMP_NB_BKPR_ZONES)
			panic("Incorrect bkpregs configuration");

		pdata->bkpregs_conf.zone1_end = fdt32_to_cpu(cuint[0]);
		bkpregs_count = fdt32_to_cpu(cuint[0]);

		pdata->bkpregs_conf.zone2_end = bkpregs_count +
						fdt32_to_cpu(cuint[1]);
	} else {
		/*
		 * Zone 3
		 * ----------------------|
		 * Protection Zone 3-RIF2|Read non-
		 * ----------------------|secure
		 * Protection Zone 3-RIF0|Write non-
		 * ----------------------|secure
		 * Protection Zone 3-RIF1|
		 * ----------------------|
		 *
		 * Zone 2
		 * ----------------------|
		 * Protection Zone 2-RIF2|Read non-
		 * ----------------------|secure
		 * Protection Zone 2-RIF1|Write secure
		 * ----------------------|
		 *
		 * Zone 1
		 * ----------------------|
		 * Protection Zone 1-RIF2|Read secure
		 * ----------------------|Write secure
		 * Protection Zone 1-RIF1|
		 * ----------------------|
		 *
		 * (BHK => First 8 registers)
		 */
		pdata->bkpregs_conf.rif_offsets = calloc(TAMP_RIF_OFFSET_CNT,
							 sizeof(uint32_t));
		if (!pdata->bkpregs_conf.rif_offsets)
			panic();

		/*
		 * 3 zones with 7 subzones in total(6 offsets):
		 * - 2 zone offsets
		 * - 4 subzones offsets
		 */
		if (lenp != sizeof(uint32_t) *
		    (TAMP_RIF_OFFSET_CNT + TAMP_NB_BKPR_ZONES))
			panic("Incorrect bkpregs configuration");

		/* Backup registers zone 1 */
		pdata->bkpregs_conf.rif_offsets[0] = fdt32_to_cpu(cuint[0]);
		pdata->bkpregs_conf.zone1_end = fdt32_to_cpu(cuint[0]) +
						fdt32_to_cpu(cuint[1]);

		bkpregs_count = pdata->bkpregs_conf.zone1_end;

		/* Backup registers zone 2 */
		pdata->bkpregs_conf.rif_offsets[1] = bkpregs_count +
						     fdt32_to_cpu(cuint[2]);
		pdata->bkpregs_conf.zone2_end = bkpregs_count +
						fdt32_to_cpu(cuint[2]) +
						fdt32_to_cpu(cuint[3]);

		bkpregs_count = pdata->bkpregs_conf.zone2_end;

		/* Backup registers zone 3 */
		pdata->bkpregs_conf.rif_offsets[2] = bkpregs_count +
						     fdt32_to_cpu(cuint[4]);
		pdata->bkpregs_conf.rif_offsets[3] = bkpregs_count +
						      fdt32_to_cpu(cuint[4]) +
						      fdt32_to_cpu(cuint[5]);
	}
}

static TEE_Result stm32_tamp_parse_fdt(const void *fdt, int node,
				       const void *compat)
{
	struct stm32_tamp_platdata *pdata = &stm32_tamp_dev->pdata;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_tamp = { };

	fdt_fill_device_info(fdt, &dt_tamp, node);

	if (dt_tamp.reg == DT_INFO_INVALID_REG ||
	    dt_tamp.reg_size == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	pdata->compat = (struct stm32_tamp_compat *)compat;
	pdata->it = dt_tamp.interrupt;
	pdata->base.pa = dt_tamp.reg;
	io_pa_or_va_secure(&pdata->base, dt_tamp.reg_size);

	res = clk_dt_get_by_index(fdt, node, 0, &pdata->clock);
	if (res)
		return res;

	parse_bkpregs_dt_conf(fdt, node);

	if (pdata->compat->tags & TAMP_HAS_RIF_SUPPORT) {
		const fdt32_t *cuint = NULL;
		unsigned int i = 0;
		int lenp = 0;

		res = stm32_rifsc_check_tdcid(&pdata->is_tdcid);
		if (res)
			return res;

		cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
		if (!cuint) {
			DMSG("No RIF configuration available");
			return TEE_SUCCESS;
		}

		pdata->conf_data = calloc(1, sizeof(*pdata->conf_data));
		if (!pdata->conf_data)
			panic();

		pdata->nb_rif_resources = (unsigned int)(lenp /
							 sizeof(uint32_t));
		assert(pdata->nb_rif_resources <= TAMP_RIF_RESOURCES);

		pdata->conf_data->cid_confs = calloc(TAMP_RIF_RESOURCES,
						     sizeof(uint32_t));
		pdata->conf_data->sec_conf = calloc(1, sizeof(uint32_t));
		pdata->conf_data->priv_conf = calloc(1, sizeof(uint32_t));
		pdata->conf_data->access_mask = calloc(1, sizeof(uint32_t));
		if (!pdata->conf_data->cid_confs ||
		    !pdata->conf_data->sec_conf ||
		    !pdata->conf_data->priv_conf ||
		    !pdata->conf_data->access_mask)
			panic("Not enough memory capacity for TAMP RIF config");

		for (i = 0; i < pdata->nb_rif_resources; i++)
			stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]),
					    pdata->conf_data,
					    TAMP_RIF_RESOURCES);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_probe(const void *fdt, int node,
				   const void *compat_data)
{
	uint32_t __maybe_unused revision = 0;
	TEE_Result res = TEE_SUCCESS;
	vaddr_t base = 0;

	stm32_tamp_dev = calloc(1, sizeof(*stm32_tamp_dev));
	if (!stm32_tamp_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = stm32_tamp_parse_fdt(fdt, node, compat_data);
	if (res)
		goto err;

	if (clk_enable(stm32_tamp_dev->pdata.clock))
		panic();

	base = io_pa_or_va(&stm32_tamp_dev->pdata.base, 1);

	stm32_tamp_dev->hwconf1 = io_read32(base + _TAMP_HWCFGR1);
	stm32_tamp_dev->hwconf2 = io_read32(base + _TAMP_HWCFGR2);

	revision = io_read32(base + _TAMP_VERR);
	FMSG("STM32 TAMPER V%"PRIx32".%"PRIu32,
	     (revision & _TAMP_VERR_MAJREV) >> 4, revision & _TAMP_VERR_MINREV);

	if (!(stm32_tamp_dev->hwconf2 & _TAMP_HWCFGR2_TZ)) {
		EMSG("TAMP doesn't support TrustZone");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err_clk;
	}

	if (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) {
		apply_rif_config();

		if (stm32_tamp_dev->pdata.is_tdcid) {
			res = stm32_tamp_apply_bkpr_rif_conf();
			if (res)
				goto err_clk;
		}
	} else {
		/*
		 * Enforce secure only access to protected TAMP registers.
		 * Allow non-secure access to monotonic counter.
		 */
		stm32_tamp_set_secure(_TAMP_SECCFGR_TAMPSEC);

		/*
		 * Enforce privilege only access to TAMP registers, backup
		 * registers and monotonic counter.
		 */
		stm32_tamp_set_privilege(_TAMP_PRIVCFG_TAMPPRIV |
					 _TAMP_PRIVCFG_BKPRWPRIV |
					 _TAMP_PRIVCFG_BKPWPRIV);
	}

	if (!(stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) ||
	    stm32_tamp_dev->pdata.is_tdcid) {
		res = stm32_tamp_set_secure_bkpregs();
		if (res)
			goto err_clk;
	}

	return TEE_SUCCESS;

err_clk:
	clk_disable(stm32_tamp_dev->pdata.clock);
err:
	if (stm32_tamp_dev->pdata.conf_data) {
		free(stm32_tamp_dev->pdata.conf_data->cid_confs);
		free(stm32_tamp_dev->pdata.conf_data->sec_conf);
		free(stm32_tamp_dev->pdata.conf_data->priv_conf);
		free(stm32_tamp_dev->pdata.conf_data->access_mask);
		free(stm32_tamp_dev->pdata.conf_data);
	}
	free(stm32_tamp_dev->pdata.bkpregs_conf.rif_offsets);
	free(stm32_tamp_dev);

	return res;
}

static const struct stm32_tamp_compat mp13_compat = {
	.nb_monotonic_counter = 2,
	.tags = TAMP_HAS_REGISTER_SECCFGR | TAMP_HAS_REGISTER_PRIVCFGR,
};

static const struct stm32_tamp_compat mp15_compat = {
	.nb_monotonic_counter = 1,
	.tags = 0,
};

static const struct stm32_tamp_compat mp25_compat = {
	.nb_monotonic_counter = 2,
	.tags = TAMP_HAS_REGISTER_SECCFGR |
		TAMP_HAS_REGISTER_PRIVCFGR |
		TAMP_HAS_RIF_SUPPORT,
};

static const struct dt_device_match stm32_tamp_match_table[] = {
	{ .compatible = "st,stm32mp25-tamp", .compat_data = &mp25_compat },
	{ .compatible = "st,stm32mp13-tamp", .compat_data = &mp13_compat },
	{ .compatible = "st,stm32-tamp", .compat_data = &mp15_compat },
	{ }
};

DEFINE_DT_DRIVER(stm32_tamp_dt_driver) = {
	.name = "stm32-tamp",
	.match_table = stm32_tamp_match_table,
	.probe = stm32_tamp_probe,
};
