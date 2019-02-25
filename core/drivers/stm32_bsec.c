// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32_bsec.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/generic_boot.h>
#include <kernel/spinlock.h>
#include <limits.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <types_ext.h>
#include <util.h>

#define BSEC_OTP_MASK			GENMASK_32(4, 0)
#define BSEC_OTP_BANK_SHIFT		5

/* Permanent lock bitmasks */
#define ADDR_LOWER_OTP_PERLOCK_SHIFT	3
#define DATA_LOWER_OTP_PERLOCK_BIT	3
#define DATA_LOWER_OTP_PERLOCK_MASK	GENMASK_32(2, 0)
#define ADDR_UPPER_OTP_PERLOCK_SHIFT	4
#define DATA_UPPER_OTP_PERLOCK_BIT	1
#define DATA_UPPER_OTP_PERLOCK_MASK	GENMASK_32(3, 0)

/* BSEC register offset */
#define BSEC_OTP_CONF_OFF		0x000U
#define BSEC_OTP_CTRL_OFF		0x004U
#define BSEC_OTP_WRDATA_OFF		0x008U
#define BSEC_OTP_STATUS_OFF		0x00CU
#define BSEC_OTP_LOCK_OFF		0x010U
#define BSEC_DEN_OFF			0x014U
#define BSEC_FEN_OFF			0x018U
#define BSEC_DISTURBED_OFF		0x01CU
#define BSEC_DISTURBED1_OFF		0x020U
#define BSEC_DISTURBED2_OFF		0x024U
#define BSEC_ERROR_OFF			0x034U
#define BSEC_ERROR1_OFF			0x038U
#define BSEC_ERROR2_OFF			0x03CU
#define BSEC_WRLOCK_OFF			0x04CU
#define BSEC_WRLOCK1_OFF		0x050U
#define BSEC_WRLOCK2_OFF		0x054U
#define BSEC_SPLOCK_OFF			0x064U
#define BSEC_SPLOCK1_OFF		0x068U
#define BSEC_SPLOCK2_OFF		0x06CU
#define BSEC_SWLOCK_OFF			0x07CU
#define BSEC_SWLOCK1_OFF		0x080U
#define BSEC_SWLOCK2_OFF		0x084U
#define BSEC_SRLOCK_OFF			0x094U
#define BSEC_SRLOCK1_OFF		0x098U
#define BSEC_SRLOCK2_OFF		0x09CU
#define BSEC_JTAG_IN_OFF		0x0ACU
#define BSEC_JTAG_OUT_OFF		0x0B0U
#define BSEC_SCRATCH_OFF		0x0B4U
#define BSEC_OTP_DATA_OFF		0x200U
#define BSEC_IPHW_CFG_OFF		0xFF0U
#define BSEC_IPVR_OFF			0xFF4U
#define BSEC_IP_ID_OFF			0xFF8U
#define BSEC_IP_MAGIC_ID_OFF		0xFFCU

/* BSEC_CONFIGURATION Register */
#define BSEC_CONF_POWER_UP_MASK		BIT(0)
#define BSEC_CONF_POWER_UP_SHIFT	0
#define BSEC_CONF_FRQ_MASK		GENMASK_32(2, 1)
#define BSEC_CONF_FRQ_SHIFT		1
#define BSEC_CONF_PRG_WIDTH_MASK	GENMASK_32(6, 3)
#define BSEC_CONF_PRG_WIDTH_SHIFT	3
#define BSEC_CONF_TREAD_MASK		GENMASK_32(8, 7)
#define BSEC_CONF_TREAD_SHIFT		7

/* BSEC_CONTROL Register */
#define BSEC_READ			0x000U
#define BSEC_WRITE			0x100U
#define BSEC_LOCK			0x200U

/* BSEC_STATUS Register */
#define BSEC_MODE_STATUS_MASK		GENMASK_32(2, 0)
#define BSEC_MODE_BUSY_MASK		BIT(3)
#define BSEC_MODE_PROGFAIL_MASK		BIT(4)
#define BSEC_MODE_PWR_MASK		BIT(5)
#define BSEC_MODE_BIST1_LOCK_MASK	BIT(6)
#define BSEC_MODE_BIST2_LOCK_MASK	BIT(7)

/* BSEC_DEBUG */
#define BSEC_HDPEN			BIT(4)
#define BSEC_SPIDEN			BIT(5)
#define BSEC_SPINDEN			BIT(6)
#define BSEC_DBGSWGEN			BIT(10)
#define BSEC_DEN_ALL_MSK		GENMASK_32(10, 0)

/*
 * OTP Lock services definition
 * Value must corresponding to the bit position in the register
 */
#define BSEC_LOCK_UPPER_OTP		0x00
#define BSEC_LOCK_DEBUG			0x02
#define BSEC_LOCK_PROGRAM		0x03

/* Timeout when polling on status */
#define BSEC_TIMEOUT_US			1000

struct bsec_dev {
	struct io_pa_va base;
	unsigned int upper_base;
	unsigned int max_id;
	bool closed_device;
};

/* Only 1 instance of BSEC is expected per platform */
static struct bsec_dev bsec_dev;

/* BSEC access protection */
static unsigned int lock = SPINLOCK_UNLOCK;

static uint32_t bsec_lock(void)
{
	return may_spin_lock(&lock);
}

static void bsec_unlock(uint32_t exceptions)
{
	may_spin_unlock(&lock, exceptions);
}

static uint32_t otp_max_id(void)
{
	return bsec_dev.max_id;
}

static uint32_t otp_bank_offset(uint32_t otp_id)
{
	assert(otp_id <= otp_max_id());

	return ((otp_id & ~BSEC_OTP_MASK) >> BSEC_OTP_BANK_SHIFT) *
		sizeof(uint32_t);
}

static vaddr_t bsec_base(void)
{
	return io_pa_or_va(&bsec_dev.base);
}

static uint32_t bsec_status(void)
{
	return io_read32(bsec_base() + BSEC_OTP_STATUS_OFF);
}

static TEE_Result check_no_error(uint32_t otp_id)
{
	uint32_t bit = BIT(otp_id & BSEC_OTP_MASK);
	uint32_t bank = otp_bank_offset(otp_id);

	if (io_read32(bsec_base() + BSEC_DISTURBED_OFF + bank) & bit)
		return TEE_ERROR_GENERIC;

	if (io_read32(bsec_base() + BSEC_ERROR_OFF + bank) & bit)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result power_up_safmem(void)
{
	uint64_t timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);

	io_mask32(bsec_base() + BSEC_OTP_CONF_OFF, BSEC_CONF_POWER_UP_MASK,
		  BSEC_CONF_POWER_UP_MASK);

	/*
	 * If a timeout is detected, test the condition again to consider
	 * cases where timeout is due to the executing TEE thread rescheduling.
	 */
	while (!timeout_elapsed(timeout_ref))
		if (bsec_status() & BSEC_MODE_PWR_MASK)
			break;

	if (bsec_status() & BSEC_MODE_PWR_MASK)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}

static TEE_Result power_down_safmem(void)
{
	uint64_t timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);

	io_mask32(bsec_base() + BSEC_OTP_CONF_OFF, 0, BSEC_CONF_POWER_UP_MASK);

	/*
	 * If a timeout is detected, test the condition again to consider
	 * cases where timeout is due to the executing TEE thread rescheduling.
	 */
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_PWR_MASK))
			break;

	if (!(bsec_status() & BSEC_MODE_PWR_MASK))
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}

TEE_Result stm32_bsec_shadow_register(uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t exceptions = 0;
	uint64_t timeout_ref = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if shadowing of OTP is locked */
	if (stm32_bsec_read_sr_lock(otp_id))
		IMSG("OTP locked, register will not be refreshed");

	exceptions = bsec_lock();

	result = power_up_safmem();
	if (result)
		return result;

	io_write32(bsec_base() + BSEC_OTP_CTRL_OFF, otp_id | BSEC_READ);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_BUSY_MASK))
			break;

	if (bsec_status() & BSEC_MODE_BUSY_MASK)
		result = TEE_ERROR_GENERIC;
	else
		result = check_no_error(otp_id);

	power_down_safmem();

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_read_otp(uint32_t *value, uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t exceptions = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = bsec_lock();

	*value = io_read32(bsec_base() + BSEC_OTP_DATA_OFF +
			   (otp_id * sizeof(uint32_t)));

	result = check_no_error(otp_id);

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_shadow_read_otp(uint32_t *otp_value, uint32_t otp_id)
{
	TEE_Result result = 0;

	result = stm32_bsec_shadow_register(otp_id);
	if (result) {
		EMSG("BSEC %" PRIu32 " Shadowing Error %x", otp_id, result);
		return result;
	}

	result = stm32_bsec_read_otp(otp_value, otp_id);
	if (result)
		EMSG("BSEC %" PRIu32 " Read Error %x", otp_id, result);

	return result;
}

TEE_Result stm32_bsec_write_otp(uint32_t value, uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t exceptions = 0;
	vaddr_t otp_data_base = bsec_base() + BSEC_OTP_DATA_OFF;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if programming of OTP is locked */
	if (stm32_bsec_read_sw_lock(otp_id))
		IMSG("OTP locked, write will be ignored");

	exceptions = bsec_lock();

	io_write32(otp_data_base + (otp_id * sizeof(uint32_t)), value);

	result = check_no_error(otp_id);

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_program_otp(uint32_t value, uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t exceptions = 0;
	uint64_t timeout_ref;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if programming of OTP is locked */
	if (stm32_bsec_read_sp_lock(otp_id))
		IMSG("OTP locked, prog will be ignored");

	if (io_read32(bsec_base() + BSEC_OTP_LOCK_OFF) & BIT(BSEC_LOCK_PROGRAM))
		IMSG("GPLOCK activated, prog will be ignored");

	exceptions = bsec_lock();

	result = power_up_safmem();
	if (result)
		return result;

	io_write32(bsec_base() + BSEC_OTP_WRDATA_OFF, value);
	io_write32(bsec_base() + BSEC_OTP_CTRL_OFF, otp_id | BSEC_WRITE);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_BUSY_MASK))
			break;

	if (bsec_status() & (BSEC_MODE_BUSY_MASK | BSEC_MODE_PROGFAIL_MASK))
		result = TEE_ERROR_GENERIC;
	else
		result = check_no_error(otp_id);

	power_down_safmem();

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t data = 0;
	uint32_t addr = 0;
	uint32_t exceptions = 0;
	vaddr_t base = bsec_base();
	uint64_t timeout_ref;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (otp_id < bsec_dev.upper_base) {
		addr = otp_id >> ADDR_LOWER_OTP_PERLOCK_SHIFT;
		data = DATA_LOWER_OTP_PERLOCK_BIT <<
		       ((otp_id & DATA_LOWER_OTP_PERLOCK_MASK) << 1U);
	} else {
		addr = (otp_id >> ADDR_UPPER_OTP_PERLOCK_SHIFT) + 2U;
		data = DATA_UPPER_OTP_PERLOCK_BIT <<
		       (otp_id & DATA_UPPER_OTP_PERLOCK_MASK);
	}

	exceptions = bsec_lock();

	result = power_up_safmem();
	if (result)
		return result;

	io_write32(base + BSEC_OTP_WRDATA_OFF, data);
	io_write32(base + BSEC_OTP_CTRL_OFF, addr | BSEC_WRITE | BSEC_LOCK);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_BUSY_MASK))
			break;

	if (bsec_status() & (BSEC_MODE_BUSY_MASK | BSEC_MODE_PROGFAIL_MASK))
		result = TEE_ERROR_BAD_PARAMETERS;
	else
		result = check_no_error(otp_id);

	power_down_safmem();

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_write_debug_conf(uint32_t value)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t masked_val = value & BSEC_DEN_ALL_MSK;
	uint32_t exceptions = 0;

	exceptions = bsec_lock();

	io_write32(bsec_base() + BSEC_DEN_OFF, value);

	if ((io_read32(bsec_base() + BSEC_DEN_OFF) ^ masked_val) == 0U)
		result = TEE_SUCCESS;

	bsec_unlock(exceptions);

	return result;
}

uint32_t stm32_bsec_read_debug_conf(void)
{
	return io_read32(bsec_base() + BSEC_DEN_OFF);
}

static bool write_bsec_lock(uint32_t otp_id, uint32_t value, size_t lock_offset)
{
	uint32_t bank = otp_bank_offset(otp_id);
	uint32_t otp_mask = BIT(otp_id & BSEC_OTP_MASK);
	vaddr_t lock_addr = bsec_base() + bank + lock_offset;
	uint32_t bank_value = 0;
	uint32_t exceptions = 0;

	if (!value)
		return false;

	exceptions = bsec_lock();

	bank_value = io_read32(lock_addr);

	if ((bank_value & otp_mask) != value) {
		/*
		 * We can write 0 in all other OTP
		 * if the lock is activated in one of other OTP.
		 * Write 0 has no effect.
		 */
		io_write32(lock_addr, bank_value | otp_mask);
	}

	bsec_unlock(exceptions);

	return true;
}

bool stm32_bsec_write_sr_lock(uint32_t otp_id, uint32_t value)
{
	return write_bsec_lock(otp_id, value, BSEC_SRLOCK_OFF);
}

bool stm32_bsec_write_sw_lock(uint32_t otp_id, uint32_t value)
{
	return write_bsec_lock(otp_id, value, BSEC_SWLOCK_OFF);
}

bool stm32_bsec_write_sp_lock(uint32_t otp_id, uint32_t value)
{
	return write_bsec_lock(otp_id, value, BSEC_SPLOCK_OFF);
}

static bool read_bsec_lock(uint32_t otp_id, size_t lock_offset)
{
	uint32_t bank = otp_bank_offset(otp_id);
	uint32_t otp_mask = BIT(otp_id & BSEC_OTP_MASK);
	vaddr_t lock_addr = bsec_base() + bank + lock_offset;

	return io_read32(lock_addr) & otp_mask;
}

bool stm32_bsec_read_sr_lock(uint32_t otp_id)
{
	return read_bsec_lock(otp_id, BSEC_SRLOCK_OFF);
}

bool stm32_bsec_read_sw_lock(uint32_t otp_id)
{
	return read_bsec_lock(otp_id, BSEC_SWLOCK_OFF);
}

bool stm32_bsec_read_sp_lock(uint32_t otp_id)
{
	return read_bsec_lock(otp_id, BSEC_SPLOCK_OFF);
}

bool stm32_bsec_wr_lock(uint32_t otp_id)
{
	uint32_t bank = otp_bank_offset(otp_id);
	uint32_t lock_bit = BIT(otp_id & BSEC_OTP_MASK);

	if (io_read32(bsec_base() + BSEC_WRLOCK_OFF + bank) & lock_bit) {
		/*
		 * In case of write don't need to write,
		 * the lock is already set.
		 */
		return true;
	}

	return false;
}

uint32_t stm32_bsec_otp_lock(uint32_t service, uint32_t value)
{
	vaddr_t addr = bsec_base() + BSEC_OTP_LOCK_OFF;

	switch (service) {
	case BSEC_LOCK_UPPER_OTP:
		io_write32(addr, value << BSEC_LOCK_UPPER_OTP);
		break;
	case BSEC_LOCK_DEBUG:
		io_write32(addr, value << BSEC_LOCK_DEBUG);
		break;
	case BSEC_LOCK_PROGRAM:
		io_write32(addr, value << BSEC_LOCK_PROGRAM);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id)
{
	if (otp_id > otp_max_id())
		return false;

	return otp_id < bsec_dev.upper_base || !bsec_dev.closed_device;
}

static TEE_Result initialize_bsec(void)
{
	struct stm32_bsec_static_cfg cfg = { 0 };
	uint32_t otp = 0;
	TEE_Result result = 0;

	stm32mp_get_bsec_static_cfg(&cfg);

	bsec_dev.base.pa = cfg.base;
	bsec_dev.upper_base = cfg.upper_start;
	bsec_dev.max_id = cfg.max_id;
	bsec_dev.closed_device = true;

	/* Disable closed device mode upon platform closed device OTP value */
	result = stm32_bsec_shadow_read_otp(&otp, cfg.closed_device_id);
	if (!result && !(otp & BIT(cfg.closed_device_position)))
		bsec_dev.closed_device = false;

	return TEE_SUCCESS;
}

driver_init(initialize_bsec);
