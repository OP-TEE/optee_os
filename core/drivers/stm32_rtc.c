// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018-2024, STMicroelectronics
 */
#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/rtc.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32_rtc.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
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

#define RTC_PRER_PREDIV_S_MASK		GENMASK_32(14, 0)

#define RTC_CR_BYPSHAD			BIT(5)
#define RTC_CR_BYPSHAD_SHIFT		U(5)
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

#define RTC_SR_TSF			BIT(3)
#define RTC_SR_TSOVF			BIT(4)

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

#define RTC_FLAGS_READ_TWICE		BIT(0)

#define TIMEOUT_US_RTC_SHADOW		U(10000)
#define MS_PER_SEC			U(1000)
#define TIMEOUT_US_RTC_GENERIC		U(100000)

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
 * @flags: RTC driver flags
 * @is_secured: True if the RTC is fully secured
 */
struct rtc_device {
	struct io_pa_va base;
	struct rtc_compat compat;
	struct clk *pclk;
	struct clk *rtc_ck;
	struct rif_conf_data *conf_data;
	unsigned int nb_res;
	uint8_t flags;
	bool is_secured;
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

/*
 * Get the subsecond value.
 */
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
 * The more PREDIV_S will be high, the more subseconds will be precise.
 */
static uint32_t stm32_rtc_get_subsecond_scale(void)
{
	return (io_read32(get_base() + RTC_PRER) & RTC_PRER_PREDIV_S_MASK) + 1;
}

/* Return relative difference in milliseconds on subsecond */
static unsigned long long stm32_rtc_diff_subs_ms(struct optee_rtc_time *cur,
						 struct optee_rtc_time *ref)
{
	if (cur->tm_ms >= ref->tm_ms)
		return cur->tm_ms - ref->tm_ms;
	else
		return ref->tm_ms - cur->tm_ms;
}

/* Fill the RTC timestamp structure from a given RTC time-in-day value */
static void stm32_rtc_fill_time(struct optee_rtc_time *tm)
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

	ssr = io_read32(base + RTC_SSR);
	tr = io_read32(base + RTC_TR);
	dr = io_read32(base + RTC_DR);

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

	tm->tm_wday = (dr & RTC_DR_WDU_MASK) >> RTC_DR_WDU_SHIFT;

	tm->tm_mday = ((dr & RTC_DR_DT_MASK) >> RTC_DR_DT_SHIFT) * 10 +
		      (dr & RTC_DR_DU_MASK);

	tm->tm_mon = ((dr & RTC_DR_MT_MASK) >> RTC_DR_MT_SHIFT) * 10 +
		     ((dr & RTC_DR_MU_MASK) >> RTC_DR_MU_SHIFT);

	tm->tm_year = ((dr & RTC_DR_YT_MASK) >> RTC_DR_YT_SHIFT) * 10 +
		      ((dr & RTC_DR_YU_MASK) >> RTC_DR_YU_SHIFT) + 2000;
}

/*
 * Here, we assume that ref is prior to current
 *
 * Return difference in milliseconds on seconds-in-day fraction
 */
static unsigned long long stm32_rtc_diff_time_ms(struct optee_rtc_time *current,
						 struct optee_rtc_time *ref)
{
	unsigned long long curr_s = 0;
	unsigned long long ref_s = 0;

	curr_s = current->tm_sec +
		 ((current->tm_min + ((current->tm_hour * 60))) * 60);

	ref_s = ref->tm_sec +
		((ref->tm_min + ((ref->tm_hour * 60))) * 60);

	return (curr_s - ref_s) * 1000;
}

/*
 * Here, we assume that ref is prior to current
 *
 * Return difference in milliseconds on day-in-year fraction
 */
static unsigned long long stm32_rtc_diff_date_ms(struct optee_rtc_time *current,
						 struct optee_rtc_time *ref)
{
	uint32_t diff_in_days = 0;
	uint32_t m = 0;
	const uint8_t month_len[] = {
		31, 28, 31, 30, 31, 30,
		31, 31, 30, 31, 30, 31
	};

	/* Get the number of non-entire month days */
	if (current->tm_mday >= ref->tm_mday)
		diff_in_days += current->tm_mday - ref->tm_mday;
	else
		diff_in_days += month_len[ref->tm_mon - 1] -
				ref->tm_mday + current->tm_mday;

	/* Get the number of entire months, and compute the related days */
	if (current->tm_mon > ref->tm_mon)
		for (m = ref->tm_mon + 1; m < current->tm_mon && m < 12; m++)
			diff_in_days += month_len[m - 1];

	if (current->tm_mon < ref->tm_mon) {
		for (m = 1; m < current->tm_mon && m < 12; m++)
			diff_in_days += month_len[m - 1];

		for (m = ref->tm_mon + 1; m < 12; m++)
			diff_in_days += month_len[m - 1];
	}

	/* Get complete years */
	if (current->tm_year > (ref->tm_year + 1))
		diff_in_days += (current->tm_year - ref->tm_year - 1) * 365;

	/* Particular cases: leap years (one day more) */
	if (diff_in_days > 0) {
		if (current->tm_year == ref->tm_year) {
			if (rtc_is_a_leap_year(current->tm_year) &&
			    ref->tm_mon <= 2 &&
			    current->tm_mon >= 3 && current->tm_mday <= 28)
				diff_in_days++;
		} else {
			uint32_t y = 0;

			/* Ref year is leap */
			if (rtc_is_a_leap_year(ref->tm_year) &&
			    ref->tm_mon <= 2 && ref->tm_mday <= 28)
				diff_in_days++;

			/* Current year is leap */
			if (rtc_is_a_leap_year(current->tm_year) &&
			    current->tm_mon >= 3)
				diff_in_days++;

			/* Interleaved years are leap */
			for (y = ref->tm_year + 1; y < current->tm_year; y++)
				if (rtc_is_a_leap_year(y))
					diff_in_days++;
		}
	}

	return (24 * 60 * 60 * 1000) * (signed long long)diff_in_days;
}

unsigned long long stm32_rtc_diff_calendar_ms(struct optee_rtc_time *cur,
					      struct optee_rtc_time *ref)
{
	unsigned long long diff_in_ms = 0;
	struct optee_rtc_time curr_t = { };
	struct optee_rtc_time ref_t = { };

	if (rtc_timecmp(cur, ref) <= 0)
		return ULLONG_MAX;

	diff_in_ms += stm32_rtc_diff_subs_ms(cur, ref);
	diff_in_ms += stm32_rtc_diff_time_ms(&curr_t, &ref_t);
	diff_in_ms += stm32_rtc_diff_date_ms(&curr_t, &ref_t);

	return (unsigned long long)diff_in_ms;
}

unsigned long long stm32_rtc_diff_calendar_tick(struct optee_rtc_time *cur,
						struct optee_rtc_time *ref,
						unsigned long long tick_rate)
{
	signed long long diff_in_tick = 0;

	if (rtc_timecmp(cur, ref) <= 0)
		panic();

	diff_in_tick += stm32_rtc_diff_subs_ms(cur, ref) *
			tick_rate / MS_PER_SEC;
	diff_in_tick += stm32_rtc_diff_time_ms(cur, ref) *
			tick_rate / MS_PER_SEC;
	diff_in_tick += stm32_rtc_diff_date_ms(cur, ref) *
			tick_rate / MS_PER_SEC;

	if (diff_in_tick < 0)
		panic("Negative time difference is not allowed");

	return (unsigned long long)diff_in_tick;
}

static TEE_Result check_rif_config(void)
{
	uint32_t rxcidcfgr = io_read32(get_base() +
				       RTC_CIDCFGR(RTC_RES_TIMESTAMP));
	uint32_t cid = (rxcidcfgr & RTC_CIDCFGR_SCID_MASK) >>
		       RTC_CIDCFGR_SCID_MASK_SHIFT;

	/* Check if TAMPTS is available for our CID */
	if ((rxcidcfgr & _CIDCFGR_CFEN) && cid != RIF_CID1)
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
		rtc_dev.is_secured = true;

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

	if (!rtc_dev.compat.has_rif_support)
		return TEE_SUCCESS;

	cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
	if (!cuint) {
		DMSG("No RIF configuration available");
		return TEE_SUCCESS;
	}

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
		stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]), rtc_dev.conf_data,
				    RTC_NB_RIF_RESOURCES);

	return TEE_SUCCESS;
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

static void stm32_rtc_exit_init_mode(void)
{
	io_clrbits32(get_base() + RTC_ICSR, RTC_ICSR_INIT);
}

static TEE_Result stm32_rtc_wait_sync(void)
{
	vaddr_t base = get_base();
	uint32_t value = 0;

	io_clrbits32(base + RTC_ICSR, RTC_ICSR_RSF);

	if (IO_READ32_POLL_TIMEOUT(base + RTC_ICSR, value,
				   value & RTC_ICSR_RSF, 10,
				   TIMEOUT_US_RTC_GENERIC))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_get_time(struct rtc *rtc __unused,
				     struct optee_rtc_time *tm)
{
	stm32_rtc_fill_time(tm);

	if (!tm->tm_mon || tm->tm_mon > 12)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * In our RTC we start :
	 * - year at 0
	 * - month at 1
	 * - day at 1
	 * - weekday at Monday = 1
	 * Here, we convert these information into something understandable
	 * by OP-TEE.
	 */
	tm->tm_mon -= 1;
	tm->tm_wday %= 7;

	return TEE_SUCCESS;
}

static TEE_Result stm32_rtc_set_time(struct rtc *rtc, struct optee_rtc_time *tm)
{
	vaddr_t rtc_base = get_base();
	uint32_t tr = 0;
	uint32_t dr = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * In our RTC we start :
	 * - year at 0
	 * - month at 1
	 * - day at 1
	 * - weekday at Monday = 1
	 * Here, we convert these information from something understandable
	 * by OP-TEE.
	 */
	tm->tm_year -= rtc->range_min.tm_year;
	tm->tm_mon += 1;
	if (!tm->tm_wday)
		tm->tm_wday = 7;

	if (tm->tm_mon > 12)
		return TEE_ERROR_BAD_PARAMETERS;

	tr = ((tm->tm_sec % 10) & RTC_TR_SU_MASK) |
	     (SHIFT_U32(tm->tm_sec / 10, RTC_TR_ST_SHIFT) & RTC_TR_ST_MASK) |
	     (SHIFT_U32(tm->tm_min % 10, RTC_TR_MNU_SHIFT) & RTC_TR_MNU_MASK) |
	     (SHIFT_U32(tm->tm_min / 10, RTC_TR_MNT_SHIFT) & RTC_TR_MNT_MASK) |
	     (SHIFT_U32(tm->tm_hour % 10, RTC_TR_HU_SHIFT) & RTC_TR_HU_MASK) |
	     (SHIFT_U32(tm->tm_hour / 10, RTC_TR_HT_SHIFT) & RTC_TR_HT_MASK);

	dr = ((tm->tm_mday % 10) & RTC_DR_DU_MASK) |
	     (SHIFT_U32(tm->tm_mday / 10, RTC_DR_DT_SHIFT) & RTC_DR_DT_MASK) |
	     (SHIFT_U32(tm->tm_mon % 10, RTC_DR_MU_SHIFT) & RTC_DR_MU_MASK) |
	     (SHIFT_U32(tm->tm_mon / 10, RTC_DR_MT_SHIFT) & RTC_DR_MT_MASK) |
	     (SHIFT_U32(tm->tm_wday, RTC_DR_WDU_SHIFT) & RTC_DR_WDU_MASK) |
	     (SHIFT_U32(tm->tm_year % 10, RTC_DR_YU_SHIFT) & RTC_DR_YU_MASK) |
	     (SHIFT_U32(tm->tm_year / 10, RTC_DR_YT_SHIFT) & RTC_DR_YT_MASK);

	stm32_rtc_write_unprotect();

	res = stm32_rtc_enter_init_mode();
	if (res)
		return res;

	io_write32(rtc_base + RTC_TR, tr);
	io_write32(rtc_base + RTC_DR, dr);

	stm32_rtc_exit_init_mode();

	res = stm32_rtc_wait_sync();
	if (res)
		return res;

	stm32_rtc_write_protect();

	return TEE_SUCCESS;
}

static const struct rtc_ops stm32_rtc_ops = {
	.get_time = stm32_rtc_get_time,
	.set_time = stm32_rtc_set_time,
};

static struct rtc stm32_rtc = {
	.ops = &stm32_rtc_ops,
	.range_min = { 2000, 1, 1, 0, 0, 0, 0 },
	.range_max = { 2099, 12, 31, 23, 59, 59, 0 },
};

static TEE_Result stm32_rtc_probe(const void *fdt, int node,
				  const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	rtc_dev.compat = *(struct rtc_compat *)compat_data;

	if (rtc_dev.compat.has_rif_support) {
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

	if (rtc_dev.compat.has_rif_support) {
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

	rtc_register(&stm32_rtc);

	return res;
}

static struct rtc_compat mp25_compat = {
	.has_seccfgr = true,
	.has_rif_support = true,
};

static struct rtc_compat mp15_compat = {
	.has_seccfgr = false,
	.has_rif_support = false,
};

static struct rtc_compat mp13_compat = {
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
