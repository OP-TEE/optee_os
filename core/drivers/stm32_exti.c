// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2025, STMicroelectronics
 */

#include <drivers/stm32_rif.h>
#include <dt-bindings/interrupt-controller/irq.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <util.h>

/* Registers */
#define _EXTI_RTSR(n)			(0x000U + (n) * 0x20U)
#define _EXTI_FTSR(n)			(0x004U + (n) * 0x20U)
#define _EXTI_RPR(n)			(0x00cU + (n) * 0x20U)
#define _EXTI_FPR(n)			(0x010U + (n) * 0x20U)
#define _EXTI_SECCFGR(n)		(0x014U + (n) * 0x20U)
#define _EXTI_PRIVCFGR(n)		(0x018U + (n) * 0x20U)
#define _EXTI_CR(n)			(0x060U + (n) * 4U)
#define _EXTI_LOCKR			0x070U
#define _EXTI_C1IMR(n)			(0x080U + (n) * 0x10U)
#define _EXTI_EnCIDCFGR(n)		(0x180U + (n) * 4U)
#define _EXTI_CmCIDCFGR(n)		(0x300U + (n) * 4U)
#define _EXTI_TRG(n)			(0x3ecU - (n) * 4U) /* HWCFGR2..4 */
#define _EXTI_HWCFGR1			0x3f0U

/* SECCFGR register bitfields */
#define _EXTI_SECCFGR_MASK		GENMASK_32(31, 0)

/* PRIVCFGR register bitfields */
#define _EXTI_PRIVCFGR_MASK		GENMASK_32(31, 0)

/* LOCKR register bitfields */
#define _EXTI_LOCKR_GLOCK		BIT(0)

/* CIDCFGR register bitfields */
#define _EXTI_CIDCFGR_CFEN		BIT(0)
#define _EXTI_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define _EXTI_CIDCFGR_SCID_SHIFT	4U
#define _EXTI_CIDCFGR_CONF_MASK		(_EXTI_CIDCFGR_CFEN | \
					 _EXTI_CIDCFGR_SCID_MASK)

/* _EXTI_HWCFGR1 bit fields */
#define _EXTI_HWCFGR1_NBEVENTS_MASK	GENMASK_32(7, 0)
#define _EXTI_HWCFGR1_NBEVENTS_SHIFT	0U
#define _EXTI_HWCFGR1_NBCPUS_MASK	GENMASK_32(11, 8)
#define _EXTI_HWCFGR1_NBCPUS_SHIFT	8U
#define _EXTI_HWCFGR1_CIDWIDTH_MASK	GENMASK_32(27, 24)
#define _EXTI_HWCFGR1_CIDWIDTH_SHIFT	24U

#define _EXTI_MAX_CR			4U
#define _EXTI_BANK_NR			3U
#define _EXTI_LINES_PER_BANK		32U

#define _EXTI_CID1			0x1U

/*
 * struct stm32_exti_itr_hierarchy - EXTI line interrupt hierarchy
 * @this: An EXTI interrupt number and its EXTI interrupt controller
 * @parent: The interrupt (number and controller) that drives the interrupt
 */
struct stm32_exti_itr_hierarchy {
	struct itr_desc this;
	struct itr_desc parent;
};

struct stm32_exti_pdata {
	struct itr_chip chip;
	vaddr_t base;
	unsigned int lock;
	uint32_t hwcfgr1;
	uint32_t trg[_EXTI_BANK_NR];
	uint32_t wake_active[_EXTI_BANK_NR];
	uint32_t mask_cache[_EXTI_BANK_NR];
	uint32_t imr_cache[_EXTI_BANK_NR];
	uint32_t seccfgr_cache[_EXTI_BANK_NR];
	uint32_t privcfgr_cache[_EXTI_BANK_NR];
	uint32_t access_mask[_EXTI_BANK_NR];
	uint32_t rtsr_cache[_EXTI_BANK_NR];
	uint32_t ftsr_cache[_EXTI_BANK_NR];
	uint32_t port_sel_cache[_EXTI_MAX_CR];
	uint32_t *e_cids;
	uint32_t *c_cids;
	struct stm32_exti_itr_hierarchy *
		hierarchy[_EXTI_LINES_PER_BANK * _EXTI_BANK_NR];
	bool glock;
};

static struct stm32_exti_pdata *
itr_chip_to_stm32_exti_pdata(struct itr_chip *chip)
{
	return container_of(chip, struct stm32_exti_pdata, chip);
}

static unsigned int stm32_exti_get_bank(uint32_t exti_line)
{
	if (exti_line < _EXTI_LINES_PER_BANK)
		return 0;

	if (exti_line < 2 * _EXTI_LINES_PER_BANK)
		return 1;

	if (exti_line < 3 * _EXTI_LINES_PER_BANK)
		return 2;

	panic();
}

static inline uint32_t stm32_exti_maxcid(const struct stm32_exti_pdata *exti)
{
	uint32_t bitfield = (exti->hwcfgr1 & _EXTI_HWCFGR1_CIDWIDTH_MASK) >>
			    _EXTI_HWCFGR1_CIDWIDTH_SHIFT;

	return BIT(bitfield) - 1;
}

static inline uint32_t stm32_exti_nbevents(const struct stm32_exti_pdata *exti)
{
	uint32_t bitfield = (exti->hwcfgr1 & _EXTI_HWCFGR1_NBEVENTS_MASK) >>
			    _EXTI_HWCFGR1_NBEVENTS_SHIFT;

	return bitfield + 1;
}

static inline uint32_t stm32_exti_nbcpus(const struct stm32_exti_pdata *exti)
{
	uint32_t bitfield = (exti->hwcfgr1 & _EXTI_HWCFGR1_NBCPUS_MASK) >>
			    _EXTI_HWCFGR1_NBCPUS_SHIFT;

	return bitfield + 1;
}

static bool
stm32_exti_event_is_configurable(const struct stm32_exti_pdata *exti,
				 unsigned int exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);

	return exti->trg[i] & mask;
}

static void stm32_exti_set_type(struct stm32_exti_pdata *exti,
				uint32_t exti_line, uint32_t type)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t r_trig = 0;
	uint32_t f_trig = 0;
	uint32_t exceptions = 0;

	switch (type) {
	case IRQ_TYPE_EDGE_RISING:
		r_trig |= mask;
		f_trig &= ~mask;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		r_trig &= ~mask;
		f_trig |= mask;
		break;
	case IRQ_TYPE_EDGE_BOTH:
		r_trig |= mask;
		f_trig |= mask;
		break;
	default:
		EMSG("Unsupported interrupt type 0x%"PRIx32, type);
		panic();
	}

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_mask32(exti->base + _EXTI_RTSR(i), r_trig, mask);
	io_mask32(exti->base + _EXTI_FTSR(i), f_trig, mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static void stm32_exti_mask(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_clrbits32(exti->base + _EXTI_C1IMR(i), mask);
	exti->mask_cache[i] &= ~mask;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static void stm32_exti_unmask(struct stm32_exti_pdata *exti,
			      uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_setbits32(exti->base + _EXTI_C1IMR(i), mask);
	exti->mask_cache[i] |= mask;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static void stm32_exti_enable_wake(struct stm32_exti_pdata *exti,
				   uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	exti->wake_active[i] |= mask;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static void stm32_exti_disable_wake(struct stm32_exti_pdata *exti,
				    uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	exti->wake_active[i] &= ~mask;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static void stm32_exti_clear(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_setbits32(exti->base + _EXTI_RPR(i), mask);
	io_setbits32(exti->base + _EXTI_FPR(i), mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static void stm32_exti_set_tz(struct stm32_exti_pdata *exti,
			      uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_setbits32(exti->base + _EXTI_SECCFGR(i), mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

static struct itr_desc *
stm32_exti_get_parent_itr(struct stm32_exti_pdata *exti, size_t it)
{
	if (!exti || it >= stm32_exti_nbevents(exti) || !exti->hierarchy[it])
		panic();

	return &exti->hierarchy[it]->parent;
}

/* Enable an interrupt */
static void stm32_exti_op_enable(struct itr_chip *chip, size_t it)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	stm32_exti_unmask(exti, it);

	interrupt_enable(parent->chip, parent->itr_num);
}

/* Disable an interrupt */
static void stm32_exti_op_disable(struct itr_chip *chip, size_t it)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	stm32_exti_mask(exti, it);

	interrupt_disable(parent->chip, parent->itr_num);
}

/* Mask an interrupt, may be called from an interrupt context */
static void stm32_exti_op_mask(struct itr_chip *chip, size_t it)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	stm32_exti_mask(exti, it);

	interrupt_mask(parent->chip, parent->itr_num);
}

/* Unmask an interrupt, may be called from an interrupt context */
static void stm32_exti_op_unmask(struct itr_chip *chip, size_t it)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	stm32_exti_unmask(exti, it);

	interrupt_unmask(parent->chip, parent->itr_num);
}

/* Raise per-cpu interrupt (optional) */
static void stm32_exti_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	if (interrupt_can_raise_pi(parent->chip))
		interrupt_raise_pi(parent->chip, parent->itr_num);
}

/* Raise a SGI (optional) */
static void stm32_exti_op_raise_sgi(struct itr_chip *chip, size_t it,
				    uint32_t cpu_mask)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	if (interrupt_can_raise_sgi(parent->chip))
		interrupt_raise_sgi(parent->chip, parent->itr_num, cpu_mask);
}

/* Set interrupt/cpu affinity (optional) */
static void stm32_exti_op_set_affinity(struct itr_chip *chip, size_t it,
				       uint8_t cpu_mask)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	if (interrupt_can_set_affinity(parent->chip))
		interrupt_set_affinity(parent->chip, parent->itr_num,
				       cpu_mask);
}

/* Enable/disable power-management wake-on of an interrupt (optional) */
static void stm32_exti_op_set_wake(struct itr_chip *chip, size_t it,
				   bool on)
{
	struct stm32_exti_pdata *exti = itr_chip_to_stm32_exti_pdata(chip);
	struct itr_desc *parent = stm32_exti_get_parent_itr(exti, it);

	if (on)
		stm32_exti_enable_wake(exti, it);
	else
		stm32_exti_disable_wake(exti, it);

	if (interrupt_can_set_wake(parent->chip))
		interrupt_set_wake(parent->chip, parent->itr_num, on);
}

static const struct itr_ops stm32_exti_ops = {
	.enable		= stm32_exti_op_enable,
	.disable	= stm32_exti_op_disable,
	.mask		= stm32_exti_op_mask,
	.unmask		= stm32_exti_op_unmask,
	.raise_pi	= stm32_exti_op_raise_pi,
	.raise_sgi	= stm32_exti_op_raise_sgi,
	.set_affinity	= stm32_exti_op_set_affinity,
	.set_wake	= stm32_exti_op_set_wake,
};
DECLARE_KEEP_PAGER(stm32_exti_ops);

static TEE_Result stm32_exti_rif_check_access(struct stm32_exti_pdata *exti,
					      uint32_t exti_line)
{
	unsigned int i = stm32_exti_get_bank(exti_line);
	uint32_t mask = BIT(exti_line % _EXTI_LINES_PER_BANK);

	/* only configured as secure and privileged */
	if (!((exti->seccfgr_cache[i] & exti->privcfgr_cache[i] &
	       exti->access_mask[i]) & mask))
		return TEE_ERROR_ACCESS_DENIED;

	if ((exti->e_cids[exti_line] & _EXTI_CIDCFGR_CFEN) &&
	    ((exti->e_cids[exti_line] & _EXTI_CIDCFGR_SCID_MASK) !=
	     SHIFT_U32(_EXTI_CID1, _EXTI_CIDCFGR_SCID_SHIFT)))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static void stm32_exti_rif_parse_dt(struct stm32_exti_pdata *exti,
				    const void *fdt, int node)
{
	struct rif_conf_data conf_data = { };
	const fdt32_t *cuint = NULL;
	uint32_t rif_conf = 0;
	unsigned int i = 0;
	int len = 0;

	if (fdt_getprop(fdt, node, "st,glocked", NULL))
		exti->glock = true;
	else
		DMSG("No global lock on RIF configuration");

	cuint = fdt_getprop(fdt, node, "st,protreg", &len);
	if (!cuint) {
		DMSG("No RIF configuration available");
		return;
	}

	exti->e_cids = calloc(stm32_exti_nbevents(exti), sizeof(uint32_t));
	exti->c_cids = calloc(stm32_exti_nbcpus(exti), sizeof(uint32_t));
	if (!exti->e_cids || !exti->c_cids)
		panic("Out of memory");

	conf_data.cid_confs   = exti->e_cids;
	conf_data.sec_conf    = exti->seccfgr_cache;
	conf_data.priv_conf   = exti->privcfgr_cache;
	conf_data.access_mask = exti->access_mask;

	for (i = 0; i < len / sizeof(uint32_t); i++) {
		rif_conf = fdt32_to_cpu(cuint[i]);

		stm32_rif_parse_cfg(rif_conf, &conf_data,
				    stm32_exti_nbevents(exti));
	}

	cuint = fdt_getprop(fdt, node, "st,proccid", &len);
	if (!cuint)
		panic("No RIF configuration available");

	for (i = 0; i < len / (2 * sizeof(uint32_t)); i++) {
		unsigned int pos = fdt32_to_cpu(cuint[2 * i]);
		uint32_t c_cid = fdt32_to_cpu(cuint[2 * i + 1]);

		if (pos == 0 || pos > stm32_exti_nbcpus(exti))
			panic("CID position out of range");

		if (c_cid > stm32_exti_maxcid(exti))
			panic("CID out of range");

		exti->c_cids[pos - 1] = SHIFT_U32(c_cid, _CIDCFGR_SCID_SHIFT) |
					_EXTI_CIDCFGR_CFEN;
	}
}

static TEE_Result stm32_exti_rif_apply(const struct stm32_exti_pdata *exti)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int bit_offset = 0;
	bool is_tdcid = false;
	uint32_t event = 0;
	unsigned int i = 0;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	/*
	 * If TDCID, clear EnCIDCFGR and CmCIDCFGR to prevent undesired
	 * events during the following configuration.
	 */

	if (is_tdcid) {
		for (event = 0; event < stm32_exti_nbevents(exti); event++) {
			i = stm32_exti_get_bank(event);
			bit_offset = event % _EXTI_LINES_PER_BANK;

			if (!(BIT(bit_offset) & exti->access_mask[i]))
				continue;

			io_clrbits32(exti->base + _EXTI_EnCIDCFGR(event),
				     _EXTI_CIDCFGR_CONF_MASK);
		}

		for (i = 0; i < stm32_exti_nbcpus(exti); i++)
			io_clrbits32(exti->base + _EXTI_CmCIDCFGR(i),
				     _EXTI_CIDCFGR_CONF_MASK);
	}

	/* Security and privilege RIF configuration */
	for (i = 0; i < _EXTI_BANK_NR; i++) {
		if (!exti->access_mask[i])
			continue;

		io_clrsetbits32(exti->base + _EXTI_PRIVCFGR(i),
				_EXTI_PRIVCFGR_MASK & exti->access_mask[i],
				exti->privcfgr_cache[i]);
		io_clrsetbits32(exti->base + _EXTI_SECCFGR(i),
				_EXTI_SECCFGR_MASK & exti->access_mask[i],
				exti->seccfgr_cache[i]);
	}

	if (!is_tdcid)
		return TEE_SUCCESS;

	/* If TDCID, configure EnCIDCFGR and CmCIDCFGR */
	for (event = 0; event < stm32_exti_nbevents(exti); event++) {
		i = stm32_exti_get_bank(event);
		bit_offset = event % _EXTI_LINES_PER_BANK;

		if (!(BIT(bit_offset) & exti->access_mask[i]))
			continue;

		io_clrsetbits32(exti->base + _EXTI_EnCIDCFGR(event),
				_EXTI_CIDCFGR_CONF_MASK, exti->e_cids[event]);
	}
	for (i = 0; i < stm32_exti_nbcpus(exti); i++) {
		if (!(exti->c_cids[i] & _EXTI_CIDCFGR_CFEN))
			continue;

		io_clrsetbits32(exti->base + _EXTI_CmCIDCFGR(i),
				_EXTI_CIDCFGR_CONF_MASK, exti->c_cids[i]);
	}

	/* If TDCID, configure global lock */
	if (exti->glock)
		io_setbits32(exti->base + _EXTI_LOCKR, _EXTI_LOCKR_GLOCK);

	return TEE_SUCCESS;
}

static void stm32_exti_rif_save(struct stm32_exti_pdata *exti)
{
	unsigned int bit_offset = 0;
	bool is_tdcid = false;
	uint32_t event = 0;
	unsigned int i = 0;

	for (i = 0; i < _EXTI_BANK_NR; i++) {
		if (!exti->access_mask[i])
			continue;

		exti->privcfgr_cache[i] =
			io_read32(exti->base + _EXTI_PRIVCFGR(i));
		exti->seccfgr_cache[i] =
			io_read32(exti->base + _EXTI_SECCFGR(i));
	}

	stm32_rifsc_check_tdcid(&is_tdcid);
	if (!is_tdcid)
		return;

	for (event = 0; event < stm32_exti_nbevents(exti); event++) {
		i = stm32_exti_get_bank(event);
		bit_offset = event % _EXTI_LINES_PER_BANK;

		if (!(BIT(bit_offset) & exti->access_mask[i]))
			continue;

		exti->e_cids[event] = io_read32(exti->base +
						_EXTI_EnCIDCFGR(event));
	}
	for (i = 0; i < stm32_exti_nbcpus(exti); i++)
		exti->c_cids[i] = io_read32(exti->base + _EXTI_CmCIDCFGR(i));
}

static void stm32_exti_pm_suspend(struct stm32_exti_pdata *exti)
{
	uint32_t base = exti->base;
	uint32_t i = 0;

	if (IS_ENABLED(CFG_STM32_RIF) && stm32_exti_maxcid(exti))
		stm32_exti_rif_save(exti);

	for (i = 0; i < _EXTI_BANK_NR; i++) {
		/* Save ftsr, rtsr and seccfgr registers */
		exti->ftsr_cache[i] = io_read32(base + _EXTI_FTSR(i));
		exti->rtsr_cache[i] = io_read32(base + _EXTI_RTSR(i));
		exti->seccfgr_cache[i] = io_read32(base + _EXTI_SECCFGR(i));
	}

	/* Save EXTI port selection */
	for (i = 0; i < _EXTI_MAX_CR; i++)
		exti->port_sel_cache[i] = io_read32(base + _EXTI_CR(i));
}

static void stm32_exti_pm_resume(struct stm32_exti_pdata *exti)
{
	uint32_t base = exti->base;
	uint32_t i = 0;

	for (i = 0; i < _EXTI_BANK_NR; i++) {
		/* Restore ftsr, rtsr and seccfgr registers */
		io_write32(base + _EXTI_FTSR(i), exti->ftsr_cache[i]);
		io_write32(base + _EXTI_RTSR(i), exti->rtsr_cache[i]);
		io_write32(base + _EXTI_SECCFGR(i), exti->seccfgr_cache[i]);
	}

	/* Restore EXTI port selection */
	for (i = 0; i < _EXTI_MAX_CR; i++)
		io_write32(base + _EXTI_CR(i), exti->port_sel_cache[i]);

	if (IS_ENABLED(CFG_STM32_RIF) && stm32_exti_maxcid(exti))
		stm32_exti_rif_apply(exti);
}

/* PM function: configure the wake_up line for OP-TEE */
static void stm32_exti_configure_wake(struct stm32_exti_pdata *exti)
{
	uint32_t i = 0;

	for (i = 0; i < _EXTI_BANK_NR; i++) {
		/* save IMR value, lost in Standby */
		exti->imr_cache[i] = io_read32(exti->base + _EXTI_C1IMR(i));
		/* deactivate in IMR the interruption activated in OP-TEE */
		io_clrbits32(exti->base + _EXTI_C1IMR(i), exti->mask_cache[i]);
		/* activate in IMR for OP-TEE wakeup interruption */
		io_setbits32(exti->base + _EXTI_C1IMR(i), exti->wake_active[i]);
	}
}

static void stm32_exti_restore_wake(struct stm32_exti_pdata *exti)
{
	uint32_t i = 0;

	/* restore saved IMR value: interruption secure/unsecure */
	for (i = 0; i < _EXTI_BANK_NR; i++)
		io_write32(exti->base + _EXTI_C1IMR(i), exti->imr_cache[i]);
}

static TEE_Result
stm32_exti_pm(enum pm_op op, unsigned int pm_hint,
	      const struct pm_callback_handle *pm_handle)
{
	struct stm32_exti_pdata *exti =
		(struct stm32_exti_pdata *)PM_CALLBACK_GET_HANDLE(pm_handle);

	if (op == PM_OP_SUSPEND)
		stm32_exti_configure_wake(exti);
	else
		stm32_exti_restore_wake(exti);

	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT))
		return TEE_SUCCESS;

	if (op == PM_OP_SUSPEND)
		stm32_exti_pm_suspend(exti);
	else
		stm32_exti_pm_resume(exti);

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(stm32_exti_pm);

static enum itr_return stm32_exti_it_handler(struct itr_handler *h)
{
	struct stm32_exti_itr_hierarchy *hierarchy = h->data;
	struct itr_desc *itr_desc = &hierarchy->this;
	struct stm32_exti_pdata *exti =
		itr_chip_to_stm32_exti_pdata(itr_desc->chip);

	interrupt_call_handlers(itr_desc->chip, itr_desc->itr_num);

	if (stm32_exti_event_is_configurable(exti, itr_desc->itr_num))
		stm32_exti_clear(exti, itr_desc->itr_num);

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(stm32_exti_it_handler);

/* Callback for "interrupts" and "interrupts-extended" DT node properties */
static TEE_Result
stm32_exti_dt_get_chip_cb(struct dt_pargs *pargs, void *priv_data,
			  struct itr_desc *itr_desc)
{
	struct stm32_exti_pdata *exti = priv_data;
	struct stm32_exti_itr_hierarchy *hierarchy = NULL;
	size_t exti_line = 0;
	uint32_t type = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pargs->args_count != 2)
		return TEE_ERROR_GENERIC;

	exti_line = pargs->args[0];
	type = pargs->args[1];

	itr_desc->chip = &exti->chip;
	itr_desc->itr_num = exti_line;

	if (exti_line >= stm32_exti_nbevents(exti))
		return TEE_ERROR_GENERIC;

	/* With RIF, check the permission */
	if (IS_ENABLED(CFG_STM32_RIF) && stm32_exti_maxcid(exti)) {
		res = stm32_exti_rif_check_access(exti, exti_line);
		if (res)
			return res;
	}

	hierarchy = exti->hierarchy[exti_line];
	if (!hierarchy) {
		hierarchy = calloc(1, sizeof(*hierarchy));
		if (!hierarchy)
			return TEE_ERROR_OUT_OF_MEMORY;
		exti->hierarchy[exti_line] = hierarchy;
	}

	hierarchy->this.chip = &exti->chip;
	hierarchy->this.itr_num = exti_line;

	res = interrupt_dt_get_by_index(pargs->fdt, pargs->phandle_node,
					exti_line,
					&hierarchy->parent.chip,
					&hierarchy->parent.itr_num);
	if (res)
		return res;

	res = interrupt_create_handler(hierarchy->parent.chip,
				       hierarchy->parent.itr_num,
				       stm32_exti_it_handler, hierarchy,
				       ITRF_TRIGGER_LEVEL, NULL);
	if (res)
		return res;

	/* set_type valid for configurable events only */
	if (stm32_exti_event_is_configurable(exti, exti_line))
		stm32_exti_set_type(exti, exti_line, type);

	/* Without RIF, predate the line by setting it as secure */
	if (!IS_ENABLED(CFG_STM32_RIF) || !stm32_exti_maxcid(exti))
		stm32_exti_set_tz(exti, exti_line);

	return TEE_SUCCESS;
}

static TEE_Result stm32_exti_probe(const void *fdt, int node,
				   const void *comp_data __unused)
{
	struct stm32_exti_pdata *exti = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct io_pa_va base = { };
	size_t reg_size = 0;
	unsigned int i = 0;

	exti = calloc(1, sizeof(*exti));
	if (!exti)
		panic("Out of memory");

	exti->lock = SPINLOCK_UNLOCK;
	exti->chip.ops = &stm32_exti_ops;
	exti->chip.name = strdup(fdt_get_name(fdt, node, NULL));

	res = itr_chip_dt_only_init(&exti->chip);
	if (res)
		panic();

	if (fdt_reg_info(fdt, node, &base.pa, &reg_size))
		panic();

	exti->base = io_pa_or_va_secure(&base, reg_size);
	assert(exti->base);

	exti->hwcfgr1 = io_read32(exti->base + _EXTI_HWCFGR1);
	for (i = 0; i < _EXTI_BANK_NR; i++)
		exti->trg[i] = io_read32(exti->base + _EXTI_TRG(i));

	if (IS_ENABLED(CFG_STM32_RIF) && stm32_exti_maxcid(exti)) {
		stm32_exti_rif_parse_dt(exti, fdt, node);
		res = stm32_exti_rif_apply(exti);
		if (res)
			goto err;
	}

	res = interrupt_register_provider(fdt, node, stm32_exti_dt_get_chip_cb,
					  exti);
	if (res)
		goto err;

	register_pm_core_service_cb(stm32_exti_pm, exti, "stm32-exti");

	return TEE_SUCCESS;

err:
	free(exti->e_cids);
	free(exti->c_cids);
	free((char *)exti->chip.name);
	free(exti);
	return res;
}

static const struct dt_device_match stm32_exti_match_table[] = {
	{ .compatible = "st,stm32mp1-exti" },
	{ }
};

DEFINE_DT_DRIVER(stm32_exti_dt_driver) = {
	.name = "stm32-exti",
	.match_table = stm32_exti_match_table,
	.probe = &stm32_exti_probe,
};
