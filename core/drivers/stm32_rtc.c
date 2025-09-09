// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018-2025, STMicroelectronics
 */
#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/rtc.h>
#include <drivers/stm32_rtc.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32_rtc.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>

/*
 * Registers
 */
#define RTC_TR				U(0x00)
#define RTC_DR				U(0x04)
#define RTC_SSR				U(0x08)
#define RTC_ICSR			U(0x0C)
#define RTC_PRER			U(0x10)
#define RTC_WUTR			U(0x14)
#define RTC_CR				U(0x18)
#define RTC_PRIVCFGR			U(0x1C)
/* RTC_SMCR is linked to RTC3v1_2 */
#define RTC_SMCR			U(0x20)
/* RTC_SECCFGR is linked to RTC3v3_2 and above */
#define RTC_SECCFGR			U(0x20)
#define RTC_WPR				U(0x24)
#define RTC_CALR			U(0x28)
#define RTC_SHIFTR			U(0x2C)
#define RTC_TSTR			U(0x30)
#define RTC_TSDR			U(0x34)
#define RTC_TSSSR			U(0x38)
#define RTC_ALRMAR			U(0x40)
#define RTC_ALRMASSR			U(0x44)
#define RTC_ALRMBR			U(0x48)
#define RTC_ALRMBSSR			U(0x4C)
#define RTC_SR				U(0x50)
#define RTC_SCR				U(0x5C)
#define RTC_OR				U(0x60)
#define RTC_CIDCFGR(x)			(U(0x80) + U(0x4) * (x))

#define RTC_TR_SU_MASK			GENMASK_32(3, 0)
#define RTC_TR_ST_MASK			GENMASK_32(6, 4)
#define RTC_TR_ST_SHIFT			U(4)
#define RTC_TR_MNU_MASK			GENMASK_32(11, 8)
#define RTC_TR_MNU_SHIFT		U(8)
#define RTC_TR_MNT_MASK			GENMASK_32(14, 12)
#define RTC_TR_MNT_SHIFT		U(12)
#define RTC_TR_HU_MASK			GENMASK_32(19, 16)
#define RTC_TR_HU_SHIFT			U(16)
#define RTC_TR_HT_MASK			GENMASK_32(21, 20)
#define RTC_TR_HT_SHIFT			U(20)
#define RTC_TR_PM			BIT(22)

#define RTC_DR_DU_MASK			GENMASK_32(3, 0)
#define RTC_DR_DT_MASK			GENMASK_32(5, 4)
#define RTC_DR_DT_SHIFT			U(4)
#define RTC_DR_MU_MASK			GENMASK_32(11, 8)
#define RTC_DR_MU_SHIFT			U(8)
#define RTC_DR_MT_MASK			BIT(12)
#define RTC_DR_MT_SHIFT			U(12)
#define RTC_DR_WDU_MASK			GENMASK_32(15, 13)
#define RTC_DR_WDU_SHIFT		U(13)
#define RTC_DR_YU_MASK			GENMASK_32(19, 16)
#define RTC_DR_YU_SHIFT			U(16)
#define RTC_DR_YT_MASK			GENMASK_32(23, 20)
#define RTC_DR_YT_SHIFT			U(20)

#define RTC_SSR_SS_MASK			GENMASK_32(15, 0)

#define RTC_ICSR_RSF			BIT(5)
#define RTC_ICSR_INITF			BIT(6)
#define RTC_ICSR_INIT			BIT(7)

#define RTC_PRER_PREDIV_S_SHIFT		U(0)
#define RTC_PRER_PREDIV_S_MASK		GENMASK_32(14, 0)
#define RTC_PRER_PREDIV_A_SHIFT		U(16)
#define RTC_PRER_PREDIV_A_MASK		GENMASK_32(22, 16)

#define RTC_CR_BYPSHAD			BIT(5)
#define RTC_CR_BYPSHAD_SHIFT		U(5)
#define RTC_CR_FMT			BIT(6)
#define RTC_CR_ALRAE			BIT(8)
#define RTC_CR_ALRAIE			BIT(12)
#define RTC_CR_TAMPTS			BIT(25)

#define RTC_PRIVCFGR_VALUES		GENMASK_32(3, 0)
#define RTC_PRIVCFGR_VALUES_TO_SHIFT	GENMASK_32(5, 4)
#define RTC_PRIVCFGR_SHIFT		U(9)
#define RTC_PRIVCFGR_MASK		(GENMASK_32(14, 13) | GENMASK_32(3, 0))
#define RTC_PRIVCFGR_FULL_PRIV		BIT(15)

#define RTC_SMCR_TS_DPROT		BIT(3)

#define RTC_SECCFGR_VALUES		GENMASK_32(3, 0)
#define RTC_SECCFGR_TS_SEC		BIT(3)
#define RTC_SECCFGR_VALUES_TO_SHIFT	GENMASK_32(5, 4)
#define RTC_SECCFGR_SHIFT		U(9)
#define RTC_SECCFGR_MASK		(GENMASK_32(14, 13) | GENMASK_32(3, 0))
#define RTC_SECCFGR_FULL_SEC		BIT(15)

#define RTC_WPR_KEY1			U(0xCA)
#define RTC_WPR_KEY2			U(0x53)
#define RTC_WPR_KEY_LOCK		U(0xFF)

#define RTC_TSDR_MU_MASK		GENMASK_32(11, 8)
#define RTC_TSDR_MU_SHIFT		U(8)
#define RTC_TSDR_DT_MASK		GENMASK_32(5, 4)
#define RTC_TSDR_DT_SHIFT		U(4)
#define RTC_TSDR_DU_MASK		GENMASK_32(3, 0)
#define RTC_TSDR_DU_SHIFT		U(0)

#define RTC_ALRMXR_SEC_UNITS_MASK	GENMASK_32(3, 0)
#define RTC_ALRMXR_SEC_UNITS_SHIFT	U(0)
#define RTC_ALRMXR_SEC_TENS_MASK	GENMASK_32(6, 4)
#define RTC_ALRMXR_SEC_TENS_SHIFT	U(4)
#define RTC_ALRMXR_SEC_MASK		BIT(7)
#define RTC_ALRMXR_MIN_UNITS_MASK	GENMASK_32(11, 8)
#define RTC_ALRMXR_MIN_UNITS_SHIFT	U(8)
#define RTC_ALRMXR_MIN_TENS_MASK	GENMASK_32(14, 12)
#define RTC_ALRMXR_MIN_TENS_SHIFT	U(12)
#define RTC_ALRMXR_MIN_MASK		BIT(15)
#define RTC_ALRMXR_HOUR_UNITS_MASK	GENMASK_32(19, 16)
#define RTC_ALRMXR_HOUR_UNITS_SHIFT	U(16)
#define RTC_ALRMXR_HOUR_TENS_MASK	GENMASK_32(21, 20)
#define RTC_ALRMXR_HOUR_TENS_SHIFT	U(20)
#define RTC_ALRMXR_PM			BIT(22)
#define RTC_ALRMXR_HOUR_MASK		BIT(23)
#define RTC_ALRMXR_DATE_UNITS_MASK	GENMASK_32(27, 24)
#define RTC_ALRMXR_DATE_UNITS_SHIFT	U(24)
#define RTC_ALRMXR_DATE_TENS_MASK	GENMASK_32(29, 28)
#define RTC_ALRMXR_DATE_TENS_SHIFT	U(28)

#define RTC_SR_ALRAF			BIT(0)
#define RTC_SR_TSF			BIT(3)
#define RTC_SR_TSOVF			BIT(4)

#define RTC_SCR_CALRAF			BIT(0)
#define RTC_SCR_CTSF			BIT(3)
#define RTC_SCR_CTSOVF			BIT(4)

#define RTC_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define RTC_CIDCFGR_SCID_MASK_SHIFT	U(4)
#define RTC_CIDCFGR_CONF_MASK		(_CIDCFGR_CFEN |	 \
					 RTC_CIDCFGR_SCID_MASK)

/*
 * RIF miscellaneous
 */
#define RTC_NB_RIF_RESOURCES		U(6)

#define RTC_RIF_FULL_PRIVILEGED		U(0x3F)
#define RTC_RIF_FULL_SECURED		U(0x3F)

#define RTC_NB_MAX_CID_SUPPORTED	U(7)

/*
 * Driver miscellaneous
 */
#define RTC_RES_TIMESTAMP		U(3)
#define RTC_RES_CALIBRATION		U(4)
#define RTC_RES_INITIALIZATION		U(5)

#define RTC_FLAGS_READ_TWICE		BIT(0)

#define TIMEOUT_US_RTC_SHADOW		U(10000)
#define TIMEOUT_US_RTC_GENERIC		U(100000)

#define YEAR_REF			ULL(2000)
#define YEAR_MAX			(YEAR_REF + ULL(99))

struct rtc_compat {
	bool has_seccfgr;
	bool has_rif_support;
};

/*
 * struct rtc_device - RTC device data
 * @base: RTC IOMEM base address
 * @compat: RTC compatible data
 * @pclk: RTC bus clock
 * @rtc_ck: RTC kernel clock
 * @conf_data: RTC RIF configuration data, when supported
 * @nb_res: Number of protectible RTC resources
 * @ts_lock: Lock used for time stamping events handling
 * @flags: RTC driver flags
 * @is_secured: True if the RTC is fully secured
 * @itr_chip: Interrupt chip
 * @itr_num: Interrupt number
 * @itr_handler: Interrupt handler
 * @notif_id: Notification ID
 * @wait_alarm_return_status: Status of the wait alarm thread
 * @rtc: information for OP-TEE RTC device
 */
struct rtc_device {
	struct io_pa_va base;
	const struct rtc_compat *compat;
	struct clk *pclk;
	struct clk *rtc_ck;
	struct rif_conf_data *conf_data;
	unsigned int nb_res;
	unsigned int ts_lock;
	uint8_t flags;
	bool is_secured;
	struct itr_chip *itr_chip;
	size_t itr_num;
	struct itr_handler *itr_handler;
	uint32_t notif_id;
	enum rtc_wait_alarm_status wait_alarm_return_status;
	struct rtc *rtc;
};

/* Expect a single RTC instance */
static struct rtc_device rtc_dev;

static vaddr_t get_base(void)
{
	assert(rtc_dev.base.pa);

	return io_pa_or_va(&rtc_dev.base, 1);
}

static void stm32_rtc_write_unprotect(void)
{
	vaddr_t rtc_base = get_base();

	io_write32(rtc_base + RTC_WPR, RTC_WPR_KEY1);
	io_write32(rtc_base + RTC_WPR, RTC_WPR_KEY2);
}

static void stm32_rtc_write_protect(void)
{
	vaddr_t rtc_base = get_base();

	io_write32(rtc_base + RTC_WPR, RTC_WPR_KEY_LOCK);
}

static bool stm32_rtc_get_bypshad(void)
{
	return io_read32(get_base() + RTC_CR) & RTC_CR_BYPSHAD;
}

/* Get the subsecond value. */
static uint32_t stm32_rtc_get_subsecond(uint32_t ssr)
{
	uint32_t prediv_s = io_read32(get_base() + RTC_PRER) &
			    RTC_PRER_PREDIV_S_MASK;

	return prediv_s - ssr;
}

/*
 * Get the subsecond scale.
 *
 * Number of subseconds in a second is linked to RTC PREDIV_S value.
 * The higher PREDIV_S is, the more subsecond is precise.
 */
static uint32_t stm32_rtc_get_subsecond_scale(void)
{
	return (io_read32(get_base() + RTC_PRER) & RTC_PRER_PREDIV_S_MASK) + 1;
}

static bool cid1_has_access(unsigned int resource)
{
	uint32_t cidcfgr = io_read32(get_base() + RTC_CIDCFGR(resource));

	return !(cidcfgr & _CIDCFGR_CFEN) ||
	       get_field_u32(cidcfgr, RTC_CIDCFGR_SCID_MASK) == RIF_CID1;
}

static TEE_Result check_rif_config(void)
{
	if (!cid1_has_access(RTC_RES_TIMESTAMP) ||
	    !cid1_has_access(RTC_RES_CALIBRATION) ||
	    !cid1_has_access(RTC_RES_INITIALIZATION))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static void apply_rif_config(bool is_tdcid)
{
	vaddr_t base = get_base();
	unsigned int shifted_values = 0;
	uint32_t seccfgr = 0;
	uint32_t privcfgr = 0;
	uint32_t access_mask_reg = 0;
	unsigned int i = 0;

	if (!rtc_dev.conf_data)
		return;

	/* Build access mask for RTC_SECCFGR and RTC_PRIVCFGR */
	for (i = 0; i < RTC_NB_RIF_RESOURCES; i++) {
		if (rtc_dev.conf_data->access_mask[0] & BIT(i)) {
			if (i <= RTC_RES_TIMESTAMP)
				access_mask_reg |= BIT(i);
			else
				access_mask_reg |= BIT(i) << RTC_SECCFGR_SHIFT;
		}
	}

	for (i = 0; i < RTC_NB_RIF_RESOURCES; i++) {
		if (!(BIT(i) & rtc_dev.conf_data->access_mask[0]))
			continue;

		/*
		 * When TDCID, OP-TEE should be the one to set the CID filtering
		 * configuration. Clearing previous configuration prevents
		 * undesired events during the only legitimate configuration.
		 */
		if (is_tdcid)
			io_clrbits32(base + RTC_CIDCFGR(i),
				     RTC_CIDCFGR_CONF_MASK);
	}

	/* Security RIF configuration */
	seccfgr = rtc_dev.conf_data->sec_conf[0];

	/* Check if all resources must be secured */
	if (seccfgr == RTC_RIF_FULL_SECURED) {
		io_setbits32(base + RTC_SECCFGR, RTC_SECCFGR_FULL_SEC);

		if (!(io_read32(base + RTC_SECCFGR) & RTC_SECCFGR_FULL_SEC))
			panic("Bad RTC seccfgr configuration");
	}

	/* Shift some values to align with the register */
	shifted_values = SHIFT_U32(seccfgr & RTC_SECCFGR_VALUES_TO_SHIFT,
				   RTC_SECCFGR_SHIFT);
	seccfgr = (seccfgr & RTC_SECCFGR_VALUES) + shifted_values;

	io_clrsetbits32(base + RTC_SECCFGR,
			RTC_SECCFGR_MASK & access_mask_reg, seccfgr);

	/* Privilege RIF configuration */
	privcfgr = rtc_dev.conf_data->priv_conf[0];

	/* Check if all resources must be privileged */
	if (privcfgr == RTC_RIF_FULL_PRIVILEGED) {
		io_setbits32(base + RTC_PRIVCFGR, RTC_PRIVCFGR_FULL_PRIV);

		if (!(io_read32(base + RTC_PRIVCFGR) & RTC_PRIVCFGR_FULL_PRIV))
			panic("Bad RTC privcfgr configuration");
	}

	/* Shift some values to align with the register */
	shifted_values = SHIFT_U32(privcfgr & RTC_PRIVCFGR_VALUES_TO_SHIFT,
				   RTC_PRIVCFGR_SHIFT);
	privcfgr = (privcfgr & RTC_PRIVCFGR_VALUES) + shifted_values;

	io_clrsetbits32(base + RTC_PRIVCFGR,
			RTC_PRIVCFGR_MASK & access_mask_reg, privcfgr);

	if (!is_tdcid)
		return;

	for (i = 0; i < RTC_NB_RIF_RESOURCES; i++) {
		if (!(BIT(i) & rtc_dev.conf_data->access_mask[0]))
			continue;
		/*
		 * When at least one resource has CID filtering enabled,
		 * the RTC_PRIVCFGR_FULL_PRIV and RTC_SECCFGR_FULL_SEC bits are
		 * cleared.
		 */
		io_clrsetbits32(base + RTC_CIDCFGR(i),
				RTC_CIDCFGR_CONF_MASK,
				rtc_dev.conf_data->cid_confs[i]);
	}
}

static void stm32_rtc_clear_events(uint32_t flags)
{
	io_write32(get_base() + RTC_SCR, flags);
}

static enum itr_return stm32_rtc_it_handler(struct itr_handler *h __unused)
{
	vaddr_t rtc_base = get_base();
	uint32_t status = io_read32(rtc_base + RTC_SR);
	uint32_t cr = io_read32(rtc_base + RTC_CR);

	if ((status & RTC_SR_ALRAF) && (cr & RTC_CR_ALRAIE)) {
		DMSG("Alarm occurred");
		/* Clear event's flags */
		stm32_rtc_clear_events(RTC_SCR_CALRAF);
		/*
		 * Notify the caller of 'stm32_rtc_wait_alarm' to re-schedule
		 * the calling thread.
		 */
		notif_send_async(rtc_dev.notif_id, 0);
	}

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(stm32_rtc_it_handler);

static TEE_Result parse_dt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	size_t reg_size = 0;
	unsigned int i = 0;
	int lenp = 0;

	if (fdt_reg_info(fdt, node, &rtc_dev.base.pa, &reg_size))
		panic();

	io_pa_or_va(&rtc_dev.base, reg_size);
	assert(rtc_dev.base.va);

	res = clk_dt_get_by_name(fdt, node, "pclk", &rtc_dev.pclk);
	if (res)
		return res;

	res = clk_dt_get_by_name(fdt, node, "rtc_ck", &rtc_dev.rtc_ck);
	if (res)
		return res;

	if (rtc_dev.compat->has_rif_support)
		cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);

	if (cuint) {
		rtc_dev.conf_data = calloc(1, sizeof(*rtc_dev.conf_data));
		if (!rtc_dev.conf_data)
			panic();

		rtc_dev.nb_res = (unsigned int)(lenp / sizeof(uint32_t));
		assert(rtc_dev.nb_res <= RTC_NB_RIF_RESOURCES);

		rtc_dev.conf_data->cid_confs = calloc(RTC_NB_RIF_RESOURCES,
						      sizeof(uint32_t));
		rtc_dev.conf_data->sec_conf = calloc(1, sizeof(uint32_t));
		rtc_dev.conf_data->priv_conf = calloc(1, sizeof(uint32_t));
		rtc_dev.conf_data->access_mask = calloc(1, sizeof(uint32_t));
		if (!rtc_dev.conf_data->cid_confs ||
		    !rtc_dev.conf_data->sec_conf ||
		    !rtc_dev.conf_data->priv_conf ||
		    !rtc_dev.conf_data->access_mask)
			panic("Not enough memory capacity for RTC RIF config");

		for (i = 0; i < rtc_dev.nb_res; i++)
			stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]),
					    rtc_dev.conf_data,
					    RTC_NB_RIF_RESOURCES);

		if (rtc_dev.conf_data->sec_conf[0] == RTC_RIF_FULL_SECURED)
			rtc_dev.is_secured = true;
	}

	cuint = fdt_getprop(fdt, node, "wakeup-source", NULL);
	/*
	 * if the wakeup-source property is not present in the DT
	 *    AND
	 *    the RTC_PTA is disable or ASYNC_NOTIF are disable
	 *    or the RTC is not secured.
	 * Then we should not register the interrupt line.
	 */
	if (!cuint && !(IS_ENABLED(CFG_RTC_PTA) &&
			IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && rtc_dev.is_secured))
		return TEE_SUCCESS;

	res = interrupt_dt_get(fdt, node, &rtc_dev.itr_chip, &rtc_dev.itr_num);
	if (res)
		goto err;

	if (cuint) {
		if (!interrupt_can_set_wake(rtc_dev.itr_chip)) {
			EMSG("%s does not have wakeup capabilities",
			     rtc_dev.itr_chip->name);
			res = TEE_ERROR_NOT_SUPPORTED;
			goto err;
		}
		rtc_dev.rtc->is_wakeup_source = true;
	}

	return TEE_SUCCESS;

err:
	if (rtc_dev.conf_data) {
		free(rtc_dev.conf_data->cid_confs);
		free(rtc_dev.conf_data->sec_conf);
		free(rtc_dev.conf_data->priv_conf);
		free(rtc_dev.conf_data->access_mask);
		free(rtc_dev.conf_data);
	}

	return res;
}

static TEE_Result stm32_rtc_enter_init_mode(void)
{
	vaddr_t base = get_base();
	uint32_t icsr = io_read32(base + RTC_ICSR);
	uint32_t value = 0;

	if (!(icsr & RTC_ICSR_INITF)) {
		icsr |= RTC_ICSR_INIT;
		io_write32(base + RTC_ICSR, icsr);

		if (IO_READ32_POLL_TIMEOUT(base + RTC_ICSR, value,
					   value & RTC_ICSR_INITF,
					   10, TIMEOUT_US_RTC_GENERIC))
			return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_exit_init_mode(void)
{
	vaddr_t base = get_base();
	uint32_t value = 0;

	io_clrbits32(base + RTC_ICSR, RTC_ICSR_INIT);
	dsb();

	io_clrbits32(base + RTC_ICSR, RTC_ICSR_RSF);

	if (IO_READ32_POLL_TIMEOUT(base + RTC_ICSR, value,
				   value & RTC_ICSR_RSF, 10,
				   TIMEOUT_US_RTC_GENERIC))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static void stm32_rtc_to_tm(uint32_t ssr, uint32_t tr, uint32_t dr,
			    struct optee_rtc_time *tm)
{
	tm->tm_hour = ((tr & RTC_TR_HT_MASK) >> RTC_TR_HT_SHIFT) * 10 +
		      ((tr & RTC_TR_HU_MASK) >> RTC_TR_HU_SHIFT);

	if (tr & RTC_TR_PM)
		tm->tm_hour += 12;

	tm->tm_ms = (stm32_rtc_get_subsecond(ssr) * MS_PER_SEC) /
		    stm32_rtc_get_subsecond_scale();

	tm->tm_sec = ((tr & RTC_TR_ST_MASK) >> RTC_TR_ST_SHIFT) * 10 +
		     (tr & RTC_TR_SU_MASK);

	tm->tm_min = ((tr & RTC_TR_MNT_MASK) >> RTC_TR_MNT_SHIFT) * 10 +
		     ((tr & RTC_TR_MNU_MASK) >> RTC_TR_MNU_SHIFT);

	tm->tm_wday = ((dr & RTC_DR_WDU_MASK) >> RTC_DR_WDU_SHIFT) % 7;

	tm->tm_mday = ((dr & RTC_DR_DT_MASK) >> RTC_DR_DT_SHIFT) * 10 +
		      (dr & RTC_DR_DU_MASK);

	tm->tm_mon = ((dr & RTC_DR_MT_MASK) >> RTC_DR_MT_SHIFT) * 10 +
		     ((dr & RTC_DR_MU_MASK) >> RTC_DR_MU_SHIFT) - 1;

	tm->tm_year = ((dr & RTC_DR_YT_MASK) >> RTC_DR_YT_SHIFT) * 10 +
		      ((dr & RTC_DR_YU_MASK) >> RTC_DR_YU_SHIFT) + YEAR_REF;
}

static TEE_Result stm32_rtc_init(void)
{
	uint32_t pred_a_max = RTC_PRER_PREDIV_A_MASK >> RTC_PRER_PREDIV_A_SHIFT;
	uint32_t pred_s_max = RTC_PRER_PREDIV_S_MASK >> RTC_PRER_PREDIV_S_SHIFT;
	unsigned long rate = clk_get_rate(rtc_dev.rtc_ck);
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = get_base();
	uint32_t pred_a = 0;
	uint32_t pred_s = 0;
	uint32_t prer = io_read32(base + RTC_PRER);
	uint32_t cr = io_read32(base + RTC_CR);

	if (rate > (pred_a_max + 1) * (pred_s_max + 1))
		panic("rtc_ck rate is too high");

	if (cr & RTC_CR_FMT && !IS_ENABLED(CFG_STM32_RTC_HIGH_ACCURACY))
		return TEE_SUCCESS;

	if (IS_ENABLED(CFG_STM32_RTC_HIGH_ACCURACY)) {
		/*
		 * Compute the prescaler values whom divides the clock in order
		 * to get a * 1 Hz output by maximizing accuracy
		 * (maximizing PREDIV_S).
		 */
		for (pred_a = 0; pred_a <= pred_a_max; pred_a++) {
			pred_s = (rate / (pred_a + 1)) - 1;
			if (pred_s <= pred_s_max &&
			    ((pred_s + 1) * (pred_a + 1)) == rate)
				break;
		}

		/*
		 * 1 Hz output not possible, give priority to RTC power
		 * consumption by choosing the higher possible value for
		 * prediv_a
		 */
		if (pred_s > pred_s_max || pred_a > pred_a_max) {
			pred_a = pred_a_max;
			pred_s = (rate / (pred_a + 1)) - 1;

			DMSG("rtc_ck is %s",
			     (rate < ((pred_a + 1) * (pred_s + 1))) ?
			     "fast" : "slow");
		}

		prer &= RTC_PRER_PREDIV_S_MASK | RTC_PRER_PREDIV_A_MASK;
		pred_s = SHIFT_U32(pred_s, RTC_PRER_PREDIV_S_SHIFT) &
			 RTC_PRER_PREDIV_S_MASK;
		pred_a = SHIFT_U32(pred_a, RTC_PRER_PREDIV_A_SHIFT) &
			 RTC_PRER_PREDIV_A_MASK;

		/* Return if there is nothing to initialize */
		if (cr & RTC_CR_FMT && prer == (pred_s | pred_a))
			return TEE_SUCCESS;
	}

	stm32_rtc_write_unprotect();

	res = stm32_rtc_enter_init_mode();
	if (res) {
		EMSG("Can't enter init mode. Fail to initialize RTC.");
		stm32_rtc_write_protect();
		return res;
	}

	if (IS_ENABLED(CFG_STM32_RTC_HIGH_ACCURACY)) {
		io_write32(base + RTC_PRER, pred_s);
		io_write32(base + RTC_PRER, pred_a | pred_s);
	}

	/* Force 24h time format */
	cr &= ~RTC_CR_FMT;
	io_write32(base + RTC_CR, cr);

	res = stm32_rtc_exit_init_mode();
	if (res)
		EMSG("Can't exit init mode. Fail to initialize RTC.");

	stm32_rtc_write_protect();

	return res;
}

static TEE_Result stm32_rtc_get_time(struct rtc *rtc __unused,
				     struct optee_rtc_time *tm)
{
	vaddr_t base = get_base();
	uint32_t ssr = 0;
	uint32_t dr = 0;
	uint32_t tr = 0;

	if (!stm32_rtc_get_bypshad()) {
		uint32_t icsr = 0;

		/* Wait calendar registers are ready */
		io_clrbits32(base + RTC_ICSR, RTC_ICSR_RSF);

		if (IO_READ32_POLL_TIMEOUT(base + RTC_ICSR, icsr,
					   icsr & RTC_ICSR_RSF, 0,
					   TIMEOUT_US_RTC_SHADOW))
			panic();
	}

	/*
	 * In our RTC we start :
	 * - year at 0
	 * - month at 1
	 * - day at 1
	 * - weekday at Monday = 1
	 * Change month value so it becomes 0=January, 1 = February, ...
	 * Change week day value so it becomes 0=Sunday, 1 = Monday, ...
	 */

	ssr = io_read32(base + RTC_SSR);
	tr = io_read32(base + RTC_TR);
	dr = io_read32(base + RTC_DR);

	stm32_rtc_to_tm(ssr, tr, dr, tm);

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_set_time(struct rtc *rtc, struct optee_rtc_time *tm)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t rtc_base = get_base();
	uint32_t tr = 0;
	uint32_t dr = 0;

	/*
	 * In our RTC we start :
	 * - year at 0
	 * - month at 1
	 * - day at 1
	 * - weekday at Monday = 1
	 * Change month value so it becomes 1=January, 2 = February, ...
	 * Change week day value so it becomes 7=Sunday, 1 = Monday, ...
	 */
	tr = ((tm->tm_sec % 10) & RTC_TR_SU_MASK) |
	     (SHIFT_U32(tm->tm_sec / 10, RTC_TR_ST_SHIFT) & RTC_TR_ST_MASK) |
	     (SHIFT_U32(tm->tm_min % 10, RTC_TR_MNU_SHIFT) & RTC_TR_MNU_MASK) |
	     (SHIFT_U32(tm->tm_min / 10, RTC_TR_MNT_SHIFT) & RTC_TR_MNT_MASK) |
	     (SHIFT_U32(tm->tm_hour % 10, RTC_TR_HU_SHIFT) & RTC_TR_HU_MASK) |
	     (SHIFT_U32(tm->tm_hour / 10, RTC_TR_HT_SHIFT) & RTC_TR_HT_MASK);

	dr = ((tm->tm_mday % 10) & RTC_DR_DU_MASK) |
	     (SHIFT_U32(tm->tm_mday / 10, RTC_DR_DT_SHIFT) & RTC_DR_DT_MASK) |
	     (SHIFT_U32((tm->tm_mon + 1) % 10, RTC_DR_MU_SHIFT) &
	      RTC_DR_MU_MASK) |
	     (SHIFT_U32((tm->tm_mon + 1) / 10, RTC_DR_MT_SHIFT) &
	      RTC_DR_MT_MASK) |
	     (SHIFT_U32(tm->tm_wday ? tm->tm_wday : 7, RTC_DR_WDU_SHIFT) &
	      RTC_DR_WDU_MASK) |
	     (SHIFT_U32((tm->tm_year - rtc->range_min.tm_year) % 10,
			RTC_DR_YU_SHIFT) & RTC_DR_YU_MASK) |
	     (SHIFT_U32((tm->tm_year - rtc->range_min.tm_year) / 10,
			RTC_DR_YT_SHIFT) & RTC_DR_YT_MASK);

	stm32_rtc_write_unprotect();

	res = stm32_rtc_enter_init_mode();
	if (res)
		goto end;

	io_write32(rtc_base + RTC_TR, tr);
	io_write32(rtc_base + RTC_DR, dr);

	res = stm32_rtc_exit_init_mode();
end:
	stm32_rtc_write_protect();

	return res;
}

TEE_Result stm32_rtc_get_timestamp(struct optee_rtc_time *tm)
{
	vaddr_t base = get_base();
	uint32_t exceptions = 0;
	uint32_t value = 0;
	uint32_t ssr = 0;
	uint32_t dr = 0;
	uint32_t tr = 0;

	exceptions = cpu_spin_lock_xsave(&rtc_dev.ts_lock);

	if (IO_READ32_POLL_TIMEOUT(base + RTC_SR, value,
				   value & RTC_SR_TSF,
				   10, TIMEOUT_US_RTC_GENERIC)) {
		cpu_spin_unlock_xrestore(&rtc_dev.ts_lock, exceptions);
		return TEE_ERROR_NO_DATA;
	}

	ssr = io_read32(base + RTC_TSSSR);
	tr = io_read32(base + RTC_TSTR);
	dr = io_read32(base + RTC_TSDR);

	io_setbits32(base + RTC_SCR, RTC_SCR_CTSF);

	/* Tamper event overflow detection */
	if (io_read32(base + RTC_SR) & RTC_SR_TSOVF) {
		io_setbits32(base + RTC_SCR, RTC_SCR_CTSOVF);
		DMSG("A timestamp event occurred while handling current event");
	}

	cpu_spin_unlock_xrestore(&rtc_dev.ts_lock, exceptions);

	stm32_rtc_to_tm(ssr, tr, dr, tm);

	/* No year timestamp available */
	tm->tm_year = 0;

	return TEE_SUCCESS;
}

TEE_Result stm32_rtc_set_tamper_timestamp(void)
{
	vaddr_t base = get_base();

	stm32_rtc_write_unprotect();

	/* Secure Timestamp bit */
	if (!rtc_dev.compat->has_seccfgr) {
		/* Inverted logic */
		io_clrbits32(base + RTC_SMCR, RTC_SMCR_TS_DPROT);
	} else {
		io_setbits32(base + RTC_SECCFGR, RTC_SECCFGR_TS_SEC);
	}

	/* Enable tamper timestamper */
	io_setbits32(base + RTC_CR, RTC_CR_TAMPTS);

	stm32_rtc_write_protect();

	return TEE_SUCCESS;
}

TEE_Result stm32_rtc_is_timestamp_enabled(bool *ret)
{
	*ret = io_read32(get_base() + RTC_CR) & RTC_CR_TAMPTS;

	return TEE_SUCCESS;
}

TEE_Result stm32_rtc_driver_is_initialized(void)
{
	if (rtc_dev.pclk)
		return TEE_SUCCESS;

	return TEE_ERROR_DEFER_DRIVER_INIT;
}

static TEE_Result stm32_rtc_read_alarm(struct rtc *rtc,
				       struct optee_rtc_alarm *alarm)
{
	struct optee_rtc_time *alarm_tm = NULL;
	struct optee_rtc_time current_tm = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t rtc_base = get_base();
	uint32_t alrmar = io_read32(rtc_base + RTC_ALRMAR);
	uint32_t cr = io_read32(rtc_base + RTC_CR);
	uint32_t status = io_read32(rtc_base + RTC_SR);

	alarm_tm = &alarm->time;

	res = stm32_rtc_get_time(rtc, &current_tm);
	if (res)
		return res;

	alarm_tm->tm_year = current_tm.tm_year;
	alarm_tm->tm_mon = current_tm.tm_mon;
	alarm_tm->tm_mday = ((alrmar & RTC_ALRMXR_DATE_UNITS_MASK) >>
			    RTC_ALRMXR_DATE_UNITS_SHIFT) +
			    ((alrmar & RTC_ALRMXR_DATE_TENS_MASK) >>
			    RTC_ALRMXR_DATE_TENS_SHIFT) * 10;
	alarm_tm->tm_hour = ((alrmar & RTC_ALRMXR_HOUR_UNITS_MASK) >>
			    RTC_ALRMXR_HOUR_UNITS_SHIFT) +
			    ((alrmar & RTC_ALRMXR_HOUR_TENS_MASK) >>
			    RTC_ALRMXR_HOUR_TENS_SHIFT) * 10;
	alarm_tm->tm_min = ((alrmar & RTC_ALRMXR_MIN_UNITS_MASK) >>
			    RTC_ALRMXR_MIN_UNITS_SHIFT) +
			   ((alrmar & RTC_ALRMXR_MIN_TENS_MASK) >>
			    RTC_ALRMXR_MIN_TENS_SHIFT) * 10;
	alarm_tm->tm_sec = ((alrmar & RTC_ALRMXR_MIN_UNITS_MASK) >>
			    RTC_ALRMXR_MIN_UNITS_SHIFT) +
			   ((alrmar & RTC_ALRMXR_MIN_TENS_MASK) >>
			    RTC_ALRMXR_MIN_TENS_SHIFT) * 10;

	if (rtc_timecmp(alarm_tm, &current_tm) < 0) {
		if (current_tm.tm_mon == 11) {
			alarm_tm->tm_mon = 0;
			alarm_tm->tm_year += 1;
		} else {
			alarm_tm->tm_mon += 1;
		}
	}

	alarm->enabled = cr & RTC_CR_ALRAE;
	alarm->pending = status & RTC_SR_ALRAF;

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_enable_alarm(struct rtc *rtc __unused, bool enabled)
{
	vaddr_t rtc_base = get_base();

	stm32_rtc_write_unprotect();

	if (enabled)
		io_setbits32(rtc_base + RTC_CR, RTC_CR_ALRAIE | RTC_CR_ALRAE);
	else
		io_clrbits32(rtc_base + RTC_CR, RTC_CR_ALRAIE | RTC_CR_ALRAE);

	stm32_rtc_clear_events(RTC_SCR_CALRAF);

	stm32_rtc_write_protect();

	return TEE_SUCCESS;
}

static void stm32_rtc_add_one_month(struct optee_rtc_time *tm)
{
	tm->tm_mon++;
	if (tm->tm_mon > 11) {
		tm->tm_mon = 0;
		tm->tm_year++;
	}

	/* Saturate to the next month last day */
	tm->tm_mday = MIN(tm->tm_mday,
			  rtc_get_month_days(tm->tm_mon, tm->tm_year));
}

static TEE_Result stm32_rtc_valid_alarm_time(struct rtc *rtc,
					     struct optee_rtc_time *tm)
{
	struct optee_rtc_time current_tm = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	struct optee_rtc_time *max = NULL;

	/*
	 * Assuming current date is M-D-Y H:M:S.
	 * RTC alarm can't be set on a specific month and year.
	 * So the valid alarm range is:
	 *	M-D-Y H:M:S < alarm <= (M+1)-D-Y H:M:S
	 */

	res = stm32_rtc_get_time(rtc, &current_tm);
	if (res)
		return res;

	/* Don't allow alarm to be set in the past. */
	if (rtc_timecmp(&current_tm, tm) >= 0)
		return TEE_ERROR_BAD_PARAMETERS;

	max = &current_tm;

	stm32_rtc_add_one_month(max);

	if (rtc_timecmp(max, tm) <= 0)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_set_alarm(struct rtc *rtc,
				      struct optee_rtc_alarm *alarm)
{
	struct optee_rtc_time *alarm_time = &alarm->time;
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t rtc_base = get_base();
	uint32_t alrmar = 0;
	uint32_t cr = io_read32(rtc_base + RTC_CR);
	uint32_t prer = io_read32(rtc_base + RTC_PRER);
	uint32_t prediv_s = prer & RTC_PRER_PREDIV_S_MASK;

	/* tm_year and tm_mon are not used because not supported by RTC */
	alrmar |= ((alarm_time->tm_mday / 10) << RTC_ALRMXR_DATE_TENS_SHIFT) &
		  RTC_ALRMXR_DATE_TENS_MASK;
	alrmar |= ((alarm_time->tm_mday % 10) << RTC_ALRMXR_DATE_UNITS_SHIFT) &
		  RTC_ALRMXR_DATE_UNITS_MASK;
	/* 24-hour format */
	alrmar &= ~RTC_ALRMXR_PM;
	alrmar |= ((alarm_time->tm_hour / 10) << RTC_ALRMXR_HOUR_TENS_SHIFT) &
		  RTC_ALRMXR_HOUR_TENS_MASK;
	alrmar |= ((alarm_time->tm_hour % 10) << RTC_ALRMXR_HOUR_UNITS_SHIFT) &
		  RTC_ALRMXR_HOUR_UNITS_MASK;
	alrmar |= ((alarm_time->tm_min / 10) << RTC_ALRMXR_MIN_TENS_SHIFT) &
		  RTC_ALRMXR_MIN_TENS_MASK;
	alrmar |= ((alarm_time->tm_min % 10) << RTC_ALRMXR_MIN_UNITS_SHIFT) &
		  RTC_ALRMXR_MIN_UNITS_MASK;
	alrmar |= ((alarm_time->tm_sec / 10) << RTC_ALRMXR_SEC_TENS_SHIFT) &
		  RTC_ALRMXR_SEC_TENS_MASK;
	alrmar |= ((alarm_time->tm_sec % 10) << RTC_ALRMXR_SEC_UNITS_SHIFT) &
		  RTC_ALRMXR_SEC_UNITS_MASK;

	if ((alrmar & !RTC_ALRMXR_SEC_MASK) && prediv_s < 3) {
		EMSG("RTC Alarm conditions not met");
		return TEE_ERROR_BAD_STATE;
	}

	stm32_rtc_write_unprotect();

	res = stm32_rtc_valid_alarm_time(rtc, alarm_time);
	if (res) {
		stm32_rtc_write_unprotect();
		return res;
	}

	/* Disable Alarm */
	cr &= ~RTC_CR_ALRAE;
	io_write32(rtc_base + RTC_CR, cr);

	io_write32(rtc_base + RTC_ALRMAR, alrmar);

	stm32_rtc_enable_alarm(rtc, alarm->enabled);

	stm32_rtc_write_protect();

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_cancel_wait_alarm(struct rtc *rtc __unused)
{
	rtc_dev.wait_alarm_return_status = RTC_WAIT_ALARM_CANCELED;
	notif_send_async(rtc_dev.notif_id, 0);

	return TEE_SUCCESS;
}

static TEE_Result
stm32_rtc_wait_alarm(struct rtc *rtc __unused,
		     enum rtc_wait_alarm_status *return_status)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	rtc_dev.wait_alarm_return_status = RTC_WAIT_ALARM_RESET;

	/* Wait until a notification arrives - blocking */
	res = notif_wait(rtc_dev.notif_id);
	if (res)
		return res;

	if (rtc_dev.wait_alarm_return_status ==
		RTC_WAIT_ALARM_CANCELED) {
		*return_status = RTC_WAIT_ALARM_CANCELED;
		stm32_rtc_enable_alarm(rtc, 0);
	} else {
		*return_status = RTC_WAIT_ALARM_ALARM_OCCURRED;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_set_alarm_wakeup_status(struct rtc *rtc __unused,
						    bool status)
{
	if (!rtc_dev.rtc->is_wakeup_source)
		return TEE_ERROR_NOT_SUPPORTED;

	interrupt_set_wake(rtc_dev.itr_chip, rtc_dev.itr_num, status);

	return TEE_SUCCESS;
}

static const struct rtc_ops stm32_rtc_ops = {
	.get_time = stm32_rtc_get_time,
	.set_time = stm32_rtc_set_time,
	.read_alarm = stm32_rtc_read_alarm,
	.set_alarm = stm32_rtc_set_alarm,
	.enable_alarm = stm32_rtc_enable_alarm,
	.wait_alarm = stm32_rtc_wait_alarm,
	.cancel_wait = stm32_rtc_cancel_wait_alarm,
	.set_alarm_wakeup_status = stm32_rtc_set_alarm_wakeup_status,
};

static struct rtc stm32_rtc = {
	.ops = &stm32_rtc_ops,
	.range_min = RTC_TIME(YEAR_REF, 0, 1, 0, 0, 0, 0, 0),
	.range_max = RTC_TIME(YEAR_MAX, 11, 31, 4, 23, 59, 59, 999),
};

static TEE_Result stm32_rtc_probe(const void *fdt, int node,
				  const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	rtc_dev.compat = compat_data;
	rtc_dev.rtc = &stm32_rtc;

	if (rtc_dev.compat->has_rif_support) {
		res = stm32_rifsc_check_tdcid(&is_tdcid);
		if (res)
			return res;
	}

	res = parse_dt(fdt, node);
	if (res) {
		memset(&rtc_dev, 0, sizeof(rtc_dev));
		return res;
	}

	/* Unbalanced clock enable to ensure RTC core clock is always on */
	res = clk_enable(rtc_dev.rtc_ck);
	if (res)
		panic("Couldn't enable RTC clock");

	if (clk_get_rate(rtc_dev.pclk) < (clk_get_rate(rtc_dev.rtc_ck) * 7))
		rtc_dev.flags |= RTC_FLAGS_READ_TWICE;

	if (rtc_dev.compat->has_rif_support) {
		res = clk_enable(rtc_dev.pclk);
		if (res)
			panic("Could not enable RTC bus clock");

		apply_rif_config(is_tdcid);

		/*
		 * Verify if applied RIF config will not disable
		 * other functionalities of this driver.
		 */
		res = check_rif_config();
		if (res)
			panic("Incompatible RTC RIF configuration");

		clk_disable(rtc_dev.pclk);
	}

	res = stm32_rtc_init();
	if (res)
		return res;

	rtc_register(&stm32_rtc);

	if (IS_ENABLED(CFG_RTC_PTA) && IS_ENABLED(CFG_CORE_ASYNC_NOTIF) &&
	    rtc_dev.is_secured && rtc_dev.itr_chip) {
		res = notif_alloc_async_value(&rtc_dev.notif_id);
		if (res)
			return res;

		res = interrupt_create_handler(rtc_dev.itr_chip,
					       rtc_dev.itr_num,
					       stm32_rtc_it_handler,
					       &rtc_dev, 0,
					       &rtc_dev.itr_handler);
		if (res)
			goto out_rtc_secured_and_itr_chip;

		/* Unbalanced clock enable to ensure IRQ interface is alive */
		res = clk_enable(rtc_dev.pclk);
		if (res)
			goto out_rtc_secured_and_itr_chip;

		interrupt_enable(rtc_dev.itr_chip, rtc_dev.itr_num);

		return TEE_SUCCESS;

out_rtc_secured_and_itr_chip:
		interrupt_remove_handler(rtc_dev.itr_handler);
		notif_free_async_value(rtc_dev.notif_id);
		return res;
	}

	return TEE_SUCCESS;
}

static const struct rtc_compat mp25_compat = {
	.has_seccfgr = true,
	.has_rif_support = true,
};

static const struct rtc_compat mp15_compat = {
	.has_seccfgr = false,
	.has_rif_support = false,
};

static const struct rtc_compat mp13_compat = {
	.has_seccfgr = true,
	.has_rif_support = false,
};

static const struct dt_device_match stm32_rtc_match_table[] = {
	{
		.compatible = "st,stm32mp25-rtc",
		.compat_data = &mp25_compat,
	},
	{
		.compatible = "st,stm32mp1-rtc",
		.compat_data = &mp15_compat,
	},
	{
		.compatible = "st,stm32mp13-rtc",
		.compat_data = &mp13_compat,
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_rtc_dt_driver) = {
	.name = "stm32-rtc",
	.match_table = stm32_rtc_match_table,
	.probe = stm32_rtc_probe,
};
