// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2020, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/stm32_bsec.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <limits.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <string.h>
#include <tee_api_defines.h>
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
#define BSEC_LOCK_PROGRAM		0x04

/* Timeout when polling on status */
#define BSEC_TIMEOUT_US			1000

#define BITS_PER_WORD		(CHAR_BIT * sizeof(uint32_t))

struct bsec_dev {
	struct io_pa_va base;
	unsigned int upper_base;
	unsigned int max_id;
	uint32_t *nsec_access;
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

static uint32_t otp_upper_base(void)
{
	return bsec_dev.upper_base;
}

static uint32_t otp_bank_offset(uint32_t otp_id)
{
	assert(otp_id <= otp_max_id());

	return ((otp_id & ~BSEC_OTP_MASK) >> BSEC_OTP_BANK_SHIFT) *
		sizeof(uint32_t);
}

static vaddr_t bsec_base(void)
{
	return io_pa_or_va_secure(&bsec_dev.base, BSEC_IP_MAGIC_ID_OFF + 1);
}

static uint32_t bsec_status(void)
{
	return io_read32(bsec_base() + BSEC_OTP_STATUS_OFF);
}

/*
 * Check that BSEC interface does not report an error
 * @otp_id : OTP number
 * @check_disturbed: check only error (false) or all sources (true)
 * Return a TEE_Result compliant value
 */
static TEE_Result check_no_error(uint32_t otp_id, bool check_disturbed)
{
	uint32_t bit = BIT(otp_id & BSEC_OTP_MASK);
	uint32_t bank = otp_bank_offset(otp_id);

	if (io_read32(bsec_base() + BSEC_ERROR_OFF + bank) & bit)
		return TEE_ERROR_GENERIC;

	if (check_disturbed &&
	    io_read32(bsec_base() + BSEC_DISTURBED_OFF + bank) & bit)
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
	bool locked = false;

	/* Check if shadowing of OTP is locked, informative only */
	result = stm32_bsec_read_sr_lock(otp_id, &locked);
	if (result)
		return result;

	if (locked)
		DMSG("BSEC shadow warning: OTP locked");

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
		result = check_no_error(otp_id, true /* check-disturbed */);

	power_down_safmem();

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_read_otp(uint32_t *value, uint32_t otp_id)
{
	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	*value = io_read32(bsec_base() + BSEC_OTP_DATA_OFF +
			   (otp_id * sizeof(uint32_t)));

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_shadow_read_otp(uint32_t *otp_value, uint32_t otp_id)
{
	TEE_Result result = 0;

	result = stm32_bsec_shadow_register(otp_id);
	if (result) {
		EMSG("BSEC %"PRIu32" Shadowing Error %#"PRIx32, otp_id, result);
		return result;
	}

	result = stm32_bsec_read_otp(otp_value, otp_id);
	if (result)
		EMSG("BSEC %"PRIu32" Read Error %#"PRIx32, otp_id, result);

	return result;
}

TEE_Result stm32_bsec_write_otp(uint32_t value, uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t exceptions = 0;
	vaddr_t otp_data_base = bsec_base() + BSEC_OTP_DATA_OFF;
	bool locked = false;

	/* Check if write of OTP is locked, informative only */
	result = stm32_bsec_read_sw_lock(otp_id, &locked);
	if (result)
		return result;

	if (locked)
		DMSG("BSEC write warning: OTP locked");

	exceptions = bsec_lock();

	io_write32(otp_data_base + (otp_id * sizeof(uint32_t)), value);

	bsec_unlock(exceptions);

	return TEE_SUCCESS;
}

#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_program_otp(uint32_t value, uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t exceptions = 0;
	uint64_t timeout_ref = 0;
	bool locked = false;

	/* Check if shadowing of OTP is locked, informative only */
	result = stm32_bsec_read_sp_lock(otp_id, &locked);
	if (result)
		return result;

	if (locked)
		DMSG("BSEC program warning: OTP locked");

	if (io_read32(bsec_base() + BSEC_OTP_LOCK_OFF) & BIT(BSEC_LOCK_PROGRAM))
		DMSG("BSEC program warning: GPLOCK activated");

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
		result = check_no_error(otp_id, true /* check-disturbed */);

	power_down_safmem();

	bsec_unlock(exceptions);

	return result;
}
#endif /*CFG_STM32_BSEC_WRITE*/

TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id)
{
	TEE_Result result = 0;
	uint32_t data = 0;
	uint32_t addr = 0;
	uint32_t exceptions = 0;
	vaddr_t base = bsec_base();
	uint64_t timeout_ref = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (otp_id < otp_upper_base()) {
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
		result = check_no_error(otp_id, false /* not-disturbed */);

	power_down_safmem();

	bsec_unlock(exceptions);

	return result;
}

#ifdef CFG_STM32_BSEC_WRITE
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
#endif /*CFG_STM32_BSEC_WRITE*/

uint32_t stm32_bsec_read_debug_conf(void)
{
	return io_read32(bsec_base() + BSEC_DEN_OFF);
}

static TEE_Result set_bsec_lock(uint32_t otp_id, size_t lock_offset)
{
	uint32_t bank = otp_bank_offset(otp_id);
	uint32_t otp_mask = BIT(otp_id & BSEC_OTP_MASK);
	vaddr_t lock_addr = bsec_base() + bank + lock_offset;
	uint32_t exceptions = 0;

	if (otp_id > STM32MP1_OTP_MAX_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = bsec_lock();

	io_write32(lock_addr, otp_mask);

	bsec_unlock(exceptions);

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_set_sr_lock(uint32_t otp_id)
{
	return set_bsec_lock(otp_id, BSEC_SRLOCK_OFF);
}

TEE_Result stm32_bsec_set_sw_lock(uint32_t otp_id)
{
	return set_bsec_lock(otp_id, BSEC_SWLOCK_OFF);
}

TEE_Result stm32_bsec_set_sp_lock(uint32_t otp_id)
{
	return set_bsec_lock(otp_id, BSEC_SPLOCK_OFF);
}

static TEE_Result read_bsec_lock(uint32_t otp_id, bool *locked,
				 size_t lock_offset)
{
	uint32_t bank = otp_bank_offset(otp_id);
	uint32_t otp_mask = BIT(otp_id & BSEC_OTP_MASK);
	vaddr_t lock_addr = bsec_base() + bank + lock_offset;

	if (otp_id > STM32MP1_OTP_MAX_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	*locked = (io_read32(lock_addr) & otp_mask) != 0;

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_read_sr_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked, BSEC_SRLOCK_OFF);
}

TEE_Result stm32_bsec_read_sw_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked, BSEC_SWLOCK_OFF);
}

TEE_Result stm32_bsec_read_sp_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked, BSEC_SPLOCK_OFF);
}

TEE_Result stm32_bsec_read_permanent_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked, BSEC_WRLOCK_OFF);
}

TEE_Result stm32_bsec_otp_lock(uint32_t service)
{
	vaddr_t addr = bsec_base() + BSEC_OTP_LOCK_OFF;

	switch (service) {
	case BSEC_LOCK_UPPER_OTP:
		io_write32(addr, BIT(BSEC_LOCK_UPPER_OTP));
		break;
	case BSEC_LOCK_DEBUG:
		io_write32(addr, BIT(BSEC_LOCK_DEBUG));
		break;
	case BSEC_LOCK_PROGRAM:
		io_write32(addr, BIT(BSEC_LOCK_PROGRAM));
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static size_t nsec_access_array_size(void)
{
	size_t upper_count = otp_max_id() - otp_upper_base() + 1;

	return ROUNDUP(upper_count, BITS_PER_WORD) / BITS_PER_WORD;
}

static bool nsec_access_granted(unsigned int index)
{
	uint32_t *array = bsec_dev.nsec_access;

	return array &&
	       (index / BITS_PER_WORD) < nsec_access_array_size() &&
	       array[index / BITS_PER_WORD] & BIT(index % BITS_PER_WORD);
}

bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id)
{
	return otp_id < otp_upper_base() ||
	       nsec_access_granted(otp_id - otp_upper_base());
}

#ifdef CFG_EMBED_DTB
static void enable_nsec_access(unsigned int otp_id)
{
	unsigned int idx = (otp_id - otp_upper_base()) / BITS_PER_WORD;

	if (otp_id < otp_upper_base())
		return;

	if (otp_id > otp_max_id() || stm32_bsec_shadow_register(otp_id))
		panic();

	bsec_dev.nsec_access[idx] |= BIT(otp_id % BITS_PER_WORD);
}

static void bsec_dt_otp_nsec_access(void *fdt, int bsec_node)
{
	int bsec_subnode = 0;

	bsec_dev.nsec_access = calloc(nsec_access_array_size(),
				      sizeof(*bsec_dev.nsec_access));
	if (!bsec_dev.nsec_access)
		panic();

	fdt_for_each_subnode(bsec_subnode, fdt, bsec_node) {
		const fdt32_t *cuint = NULL;
		unsigned int otp_id = 0;
		unsigned int i = 0;
		size_t size = 0;
		uint32_t offset = 0;
		uint32_t length = 0;

		cuint = fdt_getprop(fdt, bsec_subnode, "reg", NULL);
		assert(cuint);

		offset = fdt32_to_cpu(*cuint);
		cuint++;
		length = fdt32_to_cpu(*cuint);

		otp_id = offset / sizeof(uint32_t);

		if (otp_id < STM32MP1_UPPER_OTP_START) {
			unsigned int otp_end = ROUNDUP(offset + length,
						       sizeof(uint32_t)) /
					       sizeof(uint32_t);

			if (otp_end > STM32MP1_UPPER_OTP_START) {
				/*
				 * OTP crosses Lower/Upper boundary, consider
				 * only the upper part.
				 */
				otp_id = STM32MP1_UPPER_OTP_START;
				length -= (STM32MP1_UPPER_OTP_START *
					   sizeof(uint32_t)) - offset;
				offset = STM32MP1_UPPER_OTP_START *
					 sizeof(uint32_t);

				DMSG("OTP crosses Lower/Upper boundary");
			} else {
				continue;
			}
		}

		if (!fdt_getprop(fdt, bsec_subnode, "st,non-secure-otp", NULL))
			continue;

		if ((offset % sizeof(uint32_t)) || (length % sizeof(uint32_t)))
			panic("Unaligned non-secure OTP");

		size = length / sizeof(uint32_t);

		if (otp_id + size > STM32MP1_OTP_MAX_ID)
			panic("OTP range oversized");

		for (i = otp_id; i < otp_id + size; i++)
			enable_nsec_access(i);
	}
}

static void initialize_bsec_from_dt(void)
{
	void *fdt = NULL;
	int node = 0;
	struct dt_node_info bsec_info = { };

	fdt = get_embedded_dt();
	node = fdt_node_offset_by_compatible(fdt, 0, "st,stm32mp15-bsec");
	if (node < 0)
		panic();

	_fdt_fill_device_info(fdt, &bsec_info, node);

	if (bsec_info.reg != bsec_dev.base.pa ||
	    !(bsec_info.status & DT_STATUS_OK_SEC))
		panic();

	bsec_dt_otp_nsec_access(fdt, node);
}
#else
static void initialize_bsec_from_dt(void)
{
}
#endif /*CFG_EMBED_DTB*/

static TEE_Result initialize_bsec(void)
{
	struct stm32_bsec_static_cfg cfg = { };

	stm32mp_get_bsec_static_cfg(&cfg);

	bsec_dev.base.pa = cfg.base;
	bsec_dev.upper_base = cfg.upper_start;
	bsec_dev.max_id = cfg.max_id;

	if (IS_ENABLED(CFG_EMBED_DTB))
		initialize_bsec_from_dt();

	return TEE_SUCCESS;
}

driver_init(initialize_bsec);
