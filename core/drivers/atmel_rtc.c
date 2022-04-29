// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 *
 * Driver for AT91 RTC
 */

#include <assert.h>
#include <drivers/atmel_rtc.h>
#include <drivers/rtc.h>
#include <io.h>
#include <kernel/dt.h>
#include <matrix.h>
#include <mm/core_memprot.h>
#include <sama5d2.h>

#define RTC_VAL(reg, val)	(((val) >> RTC_## reg ## _SHIFT) & \
				 RTC_## reg ##_MASK)

#define RTC_SET_VAL(reg, val)	SHIFT_U32((val) & RTC_## reg ##_MASK, \
					  RTC_## reg ## _SHIFT)

#define RTC_CR			0x0
#define RTC_CR_UPDCAL		BIT(1)
#define RTC_CR_UPDTIM		BIT(0)

#define RTC_MR			0x4
#define RTC_MR_HR_MODE		BIT(0)
#define RTC_MR_PERSIAN		BIT(1)
#define RTC_MR_UTC		BIT(2)
#define RTC_MR_NEGPPM		BIT(4)
#define RTC_MR_CORR_SHIFT	8
#define RTC_MR_CORR_MASK	GENMASK_32(6, 0)
#define RTC_MR_CORR(val)	RTC_VAL(val, MR_CORR)
#define RTC_MR_HIGHPPM		BIT(15)

#define RTC_TIMR		0x8
#define RTC_CALR		0xC

#define RTC_SR			0x18
#define RTC_SR_ACKUPD		BIT(0)
#define RTC_SR_SEC		BIT(2)

#define RTC_SCCR		0x1C
#define RTC_SCCR_ACKCLR		BIT(0)
#define RTC_SCCR_SECCLR		BIT(2)

#define RTC_VER			0x2C
#define RTC_VER_NVTIM		BIT(0)
#define RTC_VER_NVCAL		BIT(1)

#define RTC_TSTR0		0xB0
#define RTC_TSDR0		0xB4

#define RTC_TSSR0		0xB8
#define RTC_TSSR_DET_OFFSET	16
#define RTC_TSSR_DET_COUNT	8
#define RTC_TSSR_TST_PIN	BIT(2)
#define RTC_TSSR_JTAG		BIT(3)

/* Layout of Time registers */
#define RTC_TIME_BACKUP	BIT(31)
#define RTC_TIME_HOUR_SHIFT	16
#define RTC_TIME_HOUR_MASK	GENMASK_32(5, 0)
#define RTC_TIME_MIN_SHIFT	8
#define RTC_TIME_MIN_MASK	GENMASK_32(6, 0)
#define RTC_TIME_SEC_SHIFT	0
#define RTC_TIME_SEC_MASK	GENMASK_32(6, 0)

/* Layout of Calendar registers */
#define RTC_CAL_DATE_SHIFT	24
#define RTC_CAL_DATE_MASK	GENMASK_32(5, 0)
#define RTC_CAL_DAY_SHIFT	21
#define RTC_CAL_DAY_MASK	GENMASK_32(2, 0)
#define RTC_CAL_MONTH_SHIFT	16
#define RTC_CAL_MONTH_MASK	GENMASK_32(4, 0)
#define RTC_CAL_YEAR_SHIFT	8
#define RTC_CAL_YEAR_MASK	GENMASK_32(7, 0)
#define RTC_CAL_CENT_SHIFT	0
#define RTC_CAL_CENT_MASK	GENMASK_32(6, 0)

#define ATMEL_RTC_CORR_DIVIDEND		3906000
#define ATMEL_RTC_CORR_LOW_RATIO	20

static vaddr_t rtc_base;

static uint8_t bcd_decode(uint8_t dcb_val)
{
	return (dcb_val & 0xF) + (dcb_val >> 4) * 10;
}

static uint8_t bcd_encode(uint32_t value)
{
	return ((value / 10) << 4) + value % 10;
}

static uint32_t atmel_rtc_read(unsigned int offset)
{
	return io_read32(rtc_base + offset);
}

static void atmel_rtc_write(unsigned int offset, uint32_t val)
{
	return io_write32(rtc_base + offset, val);
}

static void atmel_decode_date(unsigned int time_reg, unsigned int cal_reg,
			      struct optee_rtc_time *tm)
{
	uint32_t time = 0;
	uint32_t date = 0;

	/* Must read twice in case it changes */
	do {
		time = atmel_rtc_read(time_reg);
		date = atmel_rtc_read(cal_reg);
	} while ((time != atmel_rtc_read(time_reg)) ||
		 (date != atmel_rtc_read(cal_reg)));

	tm->tm_wday = bcd_decode(RTC_VAL(CAL_DAY, date)) - 1;
	tm->tm_mday = bcd_decode(RTC_VAL(CAL_DATE, date));
	tm->tm_mon = bcd_decode(RTC_VAL(CAL_MONTH, date)) - 1;
	tm->tm_year = bcd_decode(RTC_VAL(CAL_CENT, date)) * 100;
	tm->tm_year += bcd_decode(RTC_VAL(CAL_YEAR, date));

	tm->tm_hour = bcd_decode(RTC_VAL(TIME_HOUR, time));
	tm->tm_min = bcd_decode(RTC_VAL(TIME_MIN, time));
	tm->tm_sec = bcd_decode(RTC_VAL(TIME_SEC, time));
}

static TEE_Result atmel_rtc_get_time(struct rtc *rtc __unused,
				     struct optee_rtc_time *tm)
{
	atmel_decode_date(RTC_TIMR, RTC_CALR, tm);

	return TEE_SUCCESS;
}

TEE_Result atmel_rtc_get_tamper_timestamp(struct optee_rtc_time *tm)
{
	if (!rtc_base)
		return TEE_ERROR_NOT_SUPPORTED;

	atmel_decode_date(RTC_TSTR0, RTC_TSDR0, tm);

	return TEE_SUCCESS;
}

static TEE_Result atmel_rtc_set_time(struct rtc *rtc __unused,
				     struct optee_rtc_time *tm)
{
	uint32_t cr = 0;
	uint32_t sr = 0;
	uint32_t err = 0;

	/* First, wait for UPDCAL/UPDTIM to be 0 */
	do {
		cr = atmel_rtc_read(RTC_CR);
	} while (cr & (RTC_CR_UPDCAL | RTC_CR_UPDTIM));

	/* Stop Time/Calendar for update */
	atmel_rtc_write(RTC_CR, cr | RTC_CR_UPDCAL | RTC_CR_UPDTIM);

	do {
		sr = atmel_rtc_read(RTC_SR);
	} while (!(sr & RTC_SR_ACKUPD));

	atmel_rtc_write(RTC_SCCR, RTC_SCCR_ACKCLR);

	atmel_rtc_write(RTC_TIMR,
			RTC_SET_VAL(TIME_SEC, bcd_encode(tm->tm_sec)) |
			RTC_SET_VAL(TIME_MIN, bcd_encode(tm->tm_min)) |
			RTC_SET_VAL(TIME_HOUR, bcd_encode(tm->tm_hour)));

	atmel_rtc_write(RTC_CALR,
			RTC_SET_VAL(CAL_CENT,
				    bcd_encode(tm->tm_year / 100)) |
			RTC_SET_VAL(CAL_YEAR, bcd_encode(tm->tm_year % 100)) |
			RTC_SET_VAL(CAL_MONTH, bcd_encode(tm->tm_mon + 1)) |
			RTC_SET_VAL(CAL_DAY, bcd_encode(tm->tm_wday + 1)) |
			RTC_SET_VAL(CAL_DATE, bcd_encode(tm->tm_mday)));

	err = atmel_rtc_read(RTC_VER);
	if (err) {
		if (err & RTC_VER_NVTIM)
			DMSG("Invalid time programmed");
		if (err & RTC_VER_NVCAL)
			DMSG("Invalid date programmed");

		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Restart Time/Calendar */
	atmel_rtc_write(RTC_CR, cr);

	return TEE_SUCCESS;
}

static TEE_Result atmel_rtc_get_offset(struct rtc *rtc __unused, long *offset)
{
	uint32_t mr = atmel_rtc_read(RTC_MR);
	long val = RTC_VAL(MR_CORR, mr);

	if (!val) {
		*offset = 0;
		return TEE_SUCCESS;
	}

	val++;

	if (!(mr & RTC_MR_HIGHPPM))
		val *= ATMEL_RTC_CORR_LOW_RATIO;

	val = UDIV_ROUND_NEAREST(ATMEL_RTC_CORR_DIVIDEND, val);

	if (!(mr & RTC_MR_NEGPPM))
		val = -val;

	*offset = val;

	return TEE_SUCCESS;
}

static TEE_Result atmel_rtc_set_offset(struct rtc *rtc  __unused, long offset)
{
	long corr = 0;
	uint32_t mr = 0;

	if (offset > ATMEL_RTC_CORR_DIVIDEND / 2)
		return TEE_ERROR_BAD_PARAMETERS;
	if (offset < -ATMEL_RTC_CORR_DIVIDEND / 2)
		return TEE_ERROR_BAD_PARAMETERS;

	mr = atmel_rtc_read(RTC_MR);
	mr &= ~(RTC_MR_NEGPPM | RTC_MR_CORR_MASK | RTC_MR_HIGHPPM);

	if (offset > 0)
		mr |= RTC_MR_NEGPPM;
	else
		offset = -offset;

	/* offset less than 764 ppb, disable correction */
	if (offset < 764) {
		atmel_rtc_write(RTC_MR, mr & ~RTC_MR_NEGPPM);

		return TEE_SUCCESS;
	}

	/*
	 * 29208 ppb is the perfect cutoff between low range and high range
	 * low range values are never better than high range value after that.
	 */
	if (offset < 29208) {
		corr = UDIV_ROUND_NEAREST(ATMEL_RTC_CORR_DIVIDEND,
					  offset * ATMEL_RTC_CORR_LOW_RATIO);
	} else {
		corr = UDIV_ROUND_NEAREST(ATMEL_RTC_CORR_DIVIDEND, offset);
		mr |= RTC_MR_HIGHPPM;
	}

	corr = MIN(corr, 128);

	mr |= ((corr - 1) & RTC_MR_CORR_MASK) << RTC_MR_CORR_SHIFT;

	atmel_rtc_write(RTC_MR, mr);

	return TEE_SUCCESS;
}

static const struct rtc_ops atmel_rtc_ops = {
	.get_time = atmel_rtc_get_time,
	.set_time = atmel_rtc_set_time,
	.get_offset = atmel_rtc_get_offset,
	.set_offset = atmel_rtc_set_offset,
};

static struct rtc atmel_rtc = {
	.ops = &atmel_rtc_ops,
	.range_min = { 1900, 1, 1, 0, 0, 0, 0 },
	.range_max = { 2099, 12, 31, 23, 59, 59, 0 },
};

static TEE_Result atmel_rtc_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	size_t size = 0;

	if (rtc_base)
		return TEE_ERROR_GENERIC;

	if (_fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_BAD_PARAMETERS;

	matrix_configure_periph_secure(AT91C_ID_SYS);

	if (dt_map_dev(fdt, node, &rtc_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	atmel_rtc_write(RTC_CR, 0);
	/* Enable 24 hours Gregorian mode (this is a clear bits operation !) */
	io_clrbits32(rtc_base + RTC_MR, RTC_MR_PERSIAN | RTC_MR_UTC |
		     RTC_MR_HR_MODE);

	rtc_register(&atmel_rtc);

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_rtc_match_table[] = {
	{ .compatible = "atmel,sama5d2-rtc" },
	{ }
};

DEFINE_DT_DRIVER(atmel_rtc_dt_driver) = {
	.name = "atmel_rtc",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_rtc_match_table,
	.probe = atmel_rtc_probe,
};

