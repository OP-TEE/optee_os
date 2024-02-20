// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#include <drivers/stm32_rif.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

/* RIFSC offset register */
#define _RIFSC_RISC_SECCFGR0		U(0x10)
#define _RIFSC_RISC_PRIVCFGR0		U(0x30)
#define _RIFSC_RISC_RCFGLOCKR0		U(0x50)
#define _RIFSC_RISC_PER0_CIDCFGR	U(0x100)
#define _RIFSC_RISC_PER0_SEMCR		U(0x104)
#define _RIFSC_RIMC_CR			U(0xC00)
#define _RIFSC_RIMC_ATTR0		U(0xC10)

#define _RIFSC_HWCFGR3			U(0xFE8)
#define _RIFSC_HWCFGR2			U(0xFEC)
#define _RIFSC_HWCFGR1			U(0xFF0)
#define _RIFSC_VERR			U(0xFF4)

/* RIFSC_HWCFGR2 register fields */
#define _RIFSC_HWCFGR2_CFG1_MASK	GENMASK_32(15, 0)
#define _RIFSC_HWCFGR2_CFG1_SHIFT	U(0)
#define _RIFSC_HWCFGR2_CFG2_MASK	GENMASK_32(23, 16)
#define _RIFSC_HWCFGR2_CFG2_SHIFT	U(16)
#define _RIFSC_HWCFGR2_CFG3_MASK	GENMASK_32(31, 24)
#define _RIFSC_HWCFGR2_CFG3_SHIFT	U(24)

/* RIFSC_HWCFGR1 register fields */
#define _RIFSC_HWCFGR1_CFG1_MASK	GENMASK_32(3, 0)
#define _RIFSC_HWCFGR1_CFG1_SHIFT	U(0)
#define _RIFSC_HWCFGR1_CFG2_MASK	GENMASK_32(7, 4)
#define _RIFSC_HWCFGR1_CFG2_SHIFT	U(4)
#define _RIFSC_HWCFGR1_CFG3_MASK	GENMASK_32(11, 8)
#define _RIFSC_HWCFGR1_CFG3_SHIFT	U(8)
#define _RIFSC_HWCFGR1_CFG4_MASK	GENMASK_32(15, 12)
#define _RIFSC_HWCFGR1_CFG4_SHIFT	U(12)
#define _RIFSC_HWCFGR1_CFG5_MASK	GENMASK_32(19, 16)
#define _RIFSC_HWCFGR1_CFG5_SHIFT	U(16)
#define _RIFSC_HWCFGR1_CFG6_MASK	GENMASK_32(23, 20)
#define _RIFSC_HWCFGR1_CFG6_SHIFT	U(20)

/*
 * RISC_CR register fields
 */
#define _RIFSC_RISC_CR_GLOCK		BIT(0)

/*
 * RIMC_CR register fields
 */
#define _RIFSC_RIMC_CR_GLOCK		BIT(0)
#define _RIFSC_RIMC_CR_TDCID_MASK	GENMASK_32(6, 4)

/* RIFSC_VERR register fields */
#define _RIFSC_VERR_MINREV_MASK		GENMASK_32(3, 0)
#define _RIFSC_VERR_MINREV_SHIFT	U(0)
#define _RIFSC_VERR_MAJREV_MASK		GENMASK_32(7, 4)
#define _RIFSC_VERR_MAJREV_SHIFT	U(4)

/* Periph id per register */
#define _PERIPH_IDS_PER_REG		U(32)
#define _OFFSET_PERX_CIDCFGR		U(0x8)

#define RIFSC_RISC_CFEN_MASK		BIT(0)
#define RIFSC_RISC_CFEN_SHIFT		U(0)
#define RIFSC_RISC_SEM_EN_MASK		BIT(1)
#define RIFSC_RISC_SEM_EN_SHIFT		U(1)
#define RIFSC_RISC_SCID_MASK		GENMASK_32(6, 4)
#define RIFSC_RISC_SCID_SHIFT		U(4)
#define RIFSC_RISC_SEC_MASK		BIT(8)
#define RIFSC_RISC_SEC_SHIFT		U(8)
#define RIFSC_RISC_PRIV_MASK		BIT(9)
#define RIFSC_RISC_PRIV_SHIFT		U(9)
#define RIFSC_RISC_LOCK_MASK		BIT(10)
#define RIFSC_RISC_LOCK_SHIFT		U(10)
#define RIFSC_RISC_SEML_MASK		GENMASK_32(23, 16)
#define RIFSC_RISC_SEML_SHIFT		U(16)
#define RIFSC_RISC_PER_ID_MASK		GENMASK_32(31, 24)
#define RIFSC_RISC_PER_ID_SHIFT		U(24)

#define RIFSC_RISC_PERx_CID_MASK	(RIFSC_RISC_CFEN_MASK | \
					 RIFSC_RISC_SEM_EN_MASK | \
					 RIFSC_RISC_SCID_MASK | \
					 RIFSC_RISC_SEML_MASK)
#define RIFSC_RISC_PERx_CID_SHIFT	U(0)

#define RIFSC_RIMC_MODE_MASK		BIT(2)
#define RIFSC_RIMC_MCID_MASK		GENMASK_32(6, 4)
#define RIFSC_RIMC_MSEC_MASK		BIT(8)
#define RIFSC_RIMC_MPRIV_MASK		BIT(9)
#define RIFSC_RIMC_M_ID_MASK		GENMASK_32(23, 16)

#define RIFSC_RIMC_ATTRx_MASK		(RIFSC_RIMC_MODE_MASK | \
					 RIFSC_RIMC_MCID_MASK | \
					 RIFSC_RIMC_MSEC_MASK | \
					 RIFSC_RIMC_MPRIV_MASK)

/* max entries */
#define MAX_RIMU			U(16)
#define MAX_RISUP			U(128)

#define _RIF_FLD_GET(field, value)	(((uint32_t)(value) & \
					  (field ## _MASK)) >>\
					 (field ## _SHIFT))

struct risup_cfg {
	uint32_t cid_attr;
	uint32_t id;
	bool sec;
	bool priv;
	bool lock;
	bool pm_sem;
};

struct rimu_cfg {
	uint32_t id;
	uint32_t attr;
};

struct rifsc_driver_data {
	bool rif_en;
	bool sec_en;
	bool priv_en;
	uint8_t nb_rimu;
	uint8_t nb_risup;
	uint8_t nb_risal;
	uint8_t version;
};

struct rifsc_platdata {
	uintptr_t base;
	struct rifsc_driver_data *drv_data;
	struct risup_cfg *risup;
	unsigned int nrisup;
	struct rimu_cfg *rimu;
	unsigned int nrimu;
};

/* There is only 1 instance of the RIFSC subsystem */
static struct rifsc_driver_data rifsc_drvdata;
static struct rifsc_platdata rifsc_pdata;

static void stm32_rifsc_get_driverdata(struct rifsc_platdata *pdata)
{
	uint32_t regval = 0;

	regval = io_read32(pdata->base + _RIFSC_HWCFGR1);
	rifsc_drvdata.rif_en = _RIF_FLD_GET(_RIFSC_HWCFGR1_CFG1, regval) != 0;
	rifsc_drvdata.sec_en = _RIF_FLD_GET(_RIFSC_HWCFGR1_CFG2, regval) != 0;
	rifsc_drvdata.priv_en = _RIF_FLD_GET(_RIFSC_HWCFGR1_CFG3, regval) != 0;

	regval = io_read32(pdata->base + _RIFSC_HWCFGR2);
	rifsc_drvdata.nb_risup = _RIF_FLD_GET(_RIFSC_HWCFGR2_CFG1, regval);
	rifsc_drvdata.nb_rimu = _RIF_FLD_GET(_RIFSC_HWCFGR2_CFG2, regval);
	rifsc_drvdata.nb_risal = _RIF_FLD_GET(_RIFSC_HWCFGR2_CFG3, regval);

	pdata->drv_data = &rifsc_drvdata;

	rifsc_drvdata.version = io_read8(pdata->base + _RIFSC_VERR);

	DMSG("RIFSC version %"PRIu32".%"PRIu32,
	     _RIF_FLD_GET(_RIFSC_VERR_MAJREV, rifsc_drvdata.version),
	     _RIF_FLD_GET(_RIFSC_VERR_MINREV, rifsc_drvdata.version));

	DMSG("HW cap: enabled[rif:sec:priv]:[%s:%s:%s] nb[risup|rimu|risal]:[%"PRIu8",%"PRIu8",%"PRIu8"]",
	     rifsc_drvdata.rif_en ? "true" : "false",
	     rifsc_drvdata.sec_en ? "true" : "false",
	     rifsc_drvdata.priv_en ? "true" : "false",
	     rifsc_drvdata.nb_risup,
	     rifsc_drvdata.nb_rimu,
	     rifsc_drvdata.nb_risal);
}

static TEE_Result stm32_rifsc_glock_config(const void *fdt, int node,
					   struct rifsc_platdata *pdata)
{
	const fdt32_t *cuint = NULL;
	uint32_t glock_conf = 0;
	int len = 0;

	cuint = fdt_getprop(fdt, node, "st,glocked", &len);
	if (!cuint) {
		DMSG("No global lock on RIF configuration");
		return TEE_SUCCESS;
	}
	assert(len == sizeof(uint32_t));

	glock_conf = fdt32_to_cpu(*cuint);

	if (glock_conf & RIFSC_RIMU_GLOCK) {
		DMSG("Setting global lock on RIMU configuration");

		io_setbits32(pdata->base + _RIFSC_RIMC_CR,
			     _RIFSC_RIMC_CR_GLOCK);

		if (!(io_read32(pdata->base + _RIFSC_RIMC_CR) &
		      _RIFSC_RIMC_CR_GLOCK))
			return TEE_ERROR_ACCESS_DENIED;
	}

	if (glock_conf & RIFSC_RISUP_GLOCK) {
		DMSG("Setting global lock on RISUP configuration");

		io_setbits32(pdata->base, _RIFSC_RISC_CR_GLOCK);

		if (!(io_read32(pdata->base) & _RIFSC_RISC_CR_GLOCK))
			return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_dt_conf_risup(const void *fdt, int node,
					    struct rifsc_platdata *pdata)
{
	const fdt32_t *conf_list = NULL;
	unsigned int i = 0;
	int len = 0;

	conf_list = fdt_getprop(fdt, node, "st,protreg", &len);
	if (!conf_list) {
		DMSG("No RISUP configuration in DT");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}
	assert(!(len % sizeof(uint32_t)));

	pdata->nrisup = len / sizeof(uint32_t);
	pdata->risup = calloc(pdata->nrisup, sizeof(*pdata->risup));
	if (!pdata->risup)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < pdata->nrisup; i++) {
		uint32_t value = fdt32_to_cpu(conf_list[i]);
		struct risup_cfg *risup = pdata->risup + i;

		risup->id = _RIF_FLD_GET(RIFSC_RISC_PER_ID, value);
		risup->sec = _RIF_FLD_GET(RIFSC_RISC_SEC, value) != 0;
		risup->priv = _RIF_FLD_GET(RIFSC_RISC_PRIV, value) != 0;
		risup->lock = _RIF_FLD_GET(RIFSC_RISC_LOCK, value) != 0;
		risup->cid_attr = _RIF_FLD_GET(RIFSC_RISC_PERx_CID, value);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_dt_conf_rimu(const void *fdt, int node,
					   struct rifsc_platdata *pdata)
{
	const fdt32_t *conf_list = NULL;
	unsigned int i = 0;
	int len = 0;

	conf_list = fdt_getprop(fdt, node, "st,rimu", &len);
	if (!conf_list) {
		DMSG("No RIMU configuration in DT");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}
	assert(!(len % sizeof(uint32_t)));

	pdata->nrimu = len / sizeof(uint32_t);
	pdata->rimu = calloc(pdata->nrimu, sizeof(*pdata->rimu));
	if (!pdata->rimu)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < pdata->nrimu; i++) {
		uint32_t value = fdt32_to_cpu(*conf_list);
		struct rimu_cfg *rimu = pdata->rimu + i;

		rimu->id = _RIF_FLD_GET(RIFSC_RIMC_M_ID, value);
		rimu->attr = _RIF_FLD_GET(RIFSC_RIMC_ATTRx, value);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_parse_fdt(const void *fdt, int node,
					struct rifsc_platdata *pdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct io_pa_va base = { };
	size_t reg_size = 0;

	base.pa = fdt_reg_base_address(fdt, node);
	if (base.pa == DT_INFO_INVALID_REG)
		return TEE_ERROR_BAD_PARAMETERS;

	reg_size = fdt_reg_size(fdt, node);
	if (reg_size == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	pdata->base = io_pa_or_va_secure(&base, reg_size);

	res = stm32_rifsc_dt_conf_risup(fdt, node, pdata);
	if (res)
		return res;

	return stm32_rifsc_dt_conf_rimu(fdt, node, pdata);
}

static TEE_Result stm32_risup_cfg(struct rifsc_platdata *pdata,
				  struct risup_cfg *risup)
{
	uintptr_t offset = sizeof(uint32_t) * (risup->id / _PERIPH_IDS_PER_REG);
	uintptr_t cidcfgr_offset = _OFFSET_PERX_CIDCFGR * risup->id;
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	uint32_t shift = risup->id % _PERIPH_IDS_PER_REG;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!risup || risup->id >= drv_data->nb_risup)
		return TEE_ERROR_BAD_PARAMETERS;

	if (drv_data->sec_en)
		io_clrsetbits32(pdata->base + _RIFSC_RISC_SECCFGR0 + offset,
				BIT(shift), SHIFT_U32(risup->sec, shift));

	if (drv_data->priv_en)
		io_clrsetbits32(pdata->base + _RIFSC_RISC_PRIVCFGR0 + offset,
				BIT(shift), SHIFT_U32(risup->priv, shift));

	if (drv_data->rif_en)
		io_write32(pdata->base + _RIFSC_RISC_PER0_CIDCFGR +
			   cidcfgr_offset, risup->cid_attr);

	/* Lock configuration for this RISUP */
	if (risup->lock) {
		DMSG("Locking RIF conf for peripheral %"PRIu32, risup->id);
		io_setbits32(pdata->base + _RIFSC_RISC_RCFGLOCKR0 + offset,
			     BIT(shift));
	}

	/* Take semaphore if the resource is in semaphore mode and secured */
	if (!stm32_rif_semaphore_enabled_and_ok(risup->cid_attr, RIF_CID1) ||
	    !(io_read32(pdata->base + _RIFSC_RISC_SECCFGR0 + offset) &
	      BIT(shift))) {
		res = stm32_rif_release_semaphore(pdata->base +
						  _RIFSC_RISC_PER0_SEMCR +
						  cidcfgr_offset,
						  MAX_CID_SUPPORTED);
		if (res) {
			EMSG("Couldn't release semaphore for resource %"PRIu32,
			     risup->id);
			return TEE_ERROR_ACCESS_DENIED;
		}
	} else {
		res = stm32_rif_acquire_semaphore(pdata->base +
						  _RIFSC_RISC_PER0_SEMCR +
						  cidcfgr_offset,
						  MAX_CID_SUPPORTED);
		if (res) {
			EMSG("Couldn't acquire semaphore for resource %"PRIu32,
			     risup->id);
			return TEE_ERROR_ACCESS_DENIED;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_risup_setup(struct rifsc_platdata *pdata)
{
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int i = 0;

	for (i = 0; i < pdata->nrisup && i < drv_data->nb_risup; i++) {
		struct risup_cfg *risup = pdata->risup + i;

		res = stm32_risup_cfg(pdata, risup);
		if (res) {
			EMSG("risup cfg(%d/%d) error", i + 1, pdata->nrisup);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rimu_cfg(struct rifsc_platdata *pdata,
				 struct rimu_cfg *rimu)
{
	uintptr_t offset =  _RIFSC_RIMC_ATTR0 + (sizeof(uint32_t) * rimu->id);
	struct rifsc_driver_data *drv_data = pdata->drv_data;

	if (!rimu || rimu->id >= drv_data->nb_rimu)
		return TEE_ERROR_BAD_PARAMETERS;

	if (drv_data->rif_en)
		io_write32(pdata->base + offset, rimu->attr);

	return TEE_SUCCESS;
}

static TEE_Result stm32_rimu_setup(struct rifsc_platdata *pdata)
{
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int i = 0;

	for (i = 0; i < pdata->nrimu && i < drv_data->nb_rimu; i++) {
		struct rimu_cfg *rimu = pdata->rimu + i;

		res = stm32_rimu_cfg(pdata, rimu);
		if (res) {
			EMSG("rimu cfg(%d/%d) error", i + 1, pdata->nrimu);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_sem_pm_suspend(void)
{
	unsigned int i = 0;

	for (i = 0; i < rifsc_pdata.nrisup && i < rifsc_drvdata.nb_risup; i++) {
		uint32_t semcfgr = io_read32(rifsc_pdata.base +
					     _RIFSC_RISC_PER0_SEMCR +
					     _OFFSET_PERX_CIDCFGR * i);
		struct risup_cfg *risup = rifsc_pdata.risup + i;

		/* Save semaphores that were taken by the CID1 */
		risup->pm_sem = semcfgr & _SEMCR_MUTEX &&
				((semcfgr & _SEMCR_SEMCID_MASK) >>
				 _SEMCR_SEMCID_SHIFT) == RIF_CID1;

		FMSG("RIF semaphore %s for ID: %"PRIu32,
		     risup->pm_sem ? "SAVED" : "NOT SAVED", risup->id);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_sem_pm_resume(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int i = 0;

	for (i = 0; i < rifsc_pdata.nrisup && i < rifsc_drvdata.nb_risup; i++) {
		struct risup_cfg *risup = rifsc_pdata.risup + i;
		uintptr_t cidcfgr_offset = _OFFSET_PERX_CIDCFGR * risup->id;
		uintptr_t offset = sizeof(uint32_t) *
				   (risup->id / _PERIPH_IDS_PER_REG);
		uintptr_t perih_offset = risup->id % _PERIPH_IDS_PER_REG;
		uint32_t seccgfr = io_read32(rifsc_pdata.base +
					     _RIFSC_RISC_SECCFGR0 + offset);
		uint32_t privcgfr = io_read32(rifsc_pdata.base +
					      _RIFSC_RISC_PRIVCFGR0 + offset);
		uint32_t lockcfgr = io_read32(rifsc_pdata.base +
					      _RIFSC_RISC_RCFGLOCKR0 + offset);

		/* Update RISUPs fields */
		risup->cid_attr = io_read32(rifsc_pdata.base +
					    _RIFSC_RISC_PER0_CIDCFGR +
					    cidcfgr_offset);
		risup->sec = (seccgfr & BIT(perih_offset)) != 0;
		risup->priv = (privcgfr & BIT(perih_offset)) != 0;
		risup->lock = (lockcfgr & BIT(perih_offset)) != 0;

		/* Acquire available appropriate semaphores */
		if (!stm32_rif_semaphore_enabled_and_ok(risup->cid_attr,
							RIF_CID1) ||
		    !risup->pm_sem)
			continue;

		res = stm32_rif_acquire_semaphore(rifsc_pdata.base +
						  _RIFSC_RISC_PER0_SEMCR +
						  cidcfgr_offset,
						  MAX_CID_SUPPORTED);
		if (res) {
			EMSG("Could not acquire semaphore for resource %"PRIu32,
			     risup->id);
			return TEE_ERROR_ACCESS_DENIED;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32_rifsc_sem_pm(enum pm_op op, unsigned int pm_hint,
		   const struct pm_callback_handle *pm_handle __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pm_hint != PM_HINT_CONTEXT_STATE)
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME)
		res = stm32_rifsc_sem_pm_resume();
	else
		res = stm32_rifsc_sem_pm_suspend();

	return res;
}

TEE_Result stm32_rifsc_check_tdcid(bool *tdcid_state)
{
	if (!rifsc_pdata.base)
		return TEE_ERROR_DEFER_DRIVER_INIT;

	if (((io_read32(rifsc_pdata.base + _RIFSC_RIMC_CR) &
	     _RIFSC_RIMC_CR_TDCID_MASK)) == (RIF_CID1 << SCID_SHIFT))
		*tdcid_state = true;
	else
		*tdcid_state = false;

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_rifsc_parse_fdt(fdt, node, &rifsc_pdata);
	if (res) {
		EMSG("Could not parse RIFSC node, res = %#"PRIx32, res);
		panic();
	}

	if (!rifsc_pdata.drv_data)
		stm32_rifsc_get_driverdata(&rifsc_pdata);

	res = stm32_risup_setup(&rifsc_pdata);
	if (res) {
		EMSG("Could not setup RISUPs, res = %#"PRIx32, res);
		panic();
	}

	res = stm32_rimu_setup(&rifsc_pdata);
	if (res) {
		EMSG("Could not setup RIMUs, res = %#"PRIx32, res);
		panic();
	}

	res = stm32_rifsc_glock_config(fdt, node, &rifsc_pdata);
	if (res)
		panic("Couldn't lock RIFSC configuration");

	register_pm_core_service_cb(stm32_rifsc_sem_pm, NULL,
				    "stm32-rifsc-semaphores");

	return TEE_SUCCESS;
}

static const struct dt_device_match rifsc_match_table[] = {
	{ .compatible = "st,stm32mp25-rifsc" },
	{ }
};

DEFINE_DT_DRIVER(rifsc_dt_driver) = {
	.name = "stm32-rifsc",
	.match_table = rifsc_match_table,
	.probe = stm32_rifsc_probe,
};
