// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2021, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/stm32_bsec.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/pm.h>
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

#ifdef CFG_STM32MP13
#define DT_BSEC_COMPAT "st,stm32mp13-bsec"
#endif
#ifdef CFG_STM32MP15
#define DT_BSEC_COMPAT "st,stm32mp15-bsec"
#endif

#define BSEC_OTP_MASK			GENMASK_32(4, 0)
#define BSEC_OTP_BANK_SHIFT		U(5)

/* Permanent lock bitmasks */
#define DATA_LOWER_OTP_PERLOCK_BIT	U(3)
#define DATA_UPPER_OTP_PERLOCK_BIT	U(1)

/* BSEC register offset */
#define BSEC_OTP_CONF_OFF		U(0x000)
#define BSEC_OTP_CTRL_OFF		U(0x004)
#define BSEC_OTP_WRDATA_OFF		U(0x008)
#define BSEC_OTP_STATUS_OFF		U(0x00C)
#define BSEC_OTP_LOCK_OFF		U(0x010)
#define BSEC_DEN_OFF			U(0x014)
#define BSEC_FEN_OFF			U(0x018)
#define BSEC_DISTURBED_OFF		U(0x01C)
#define BSEC_DISTURBED1_OFF		U(0x020)
#define BSEC_DISTURBED2_OFF		U(0x024)
#define BSEC_ERROR_OFF			U(0x034)
#define BSEC_ERROR1_OFF			U(0x038)
#define BSEC_ERROR2_OFF			U(0x03C)
#define BSEC_WRLOCK_OFF			U(0x04C)
#define BSEC_WRLOCK1_OFF		U(0x050)
#define BSEC_WRLOCK2_OFF		U(0x054)
#define BSEC_SPLOCK_OFF			U(0x064)
#define BSEC_SPLOCK1_OFF		U(0x068)
#define BSEC_SPLOCK2_OFF		U(0x06C)
#define BSEC_SWLOCK_OFF			U(0x07C)
#define BSEC_SWLOCK1_OFF		U(0x080)
#define BSEC_SWLOCK2_OFF		U(0x084)
#define BSEC_SRLOCK_OFF			U(0x094)
#define BSEC_SRLOCK1_OFF		U(0x098)
#define BSEC_SRLOCK2_OFF		U(0x09C)
#define BSEC_JTAG_IN_OFF		U(0x0AC)
#define BSEC_JTAG_OUT_OFF		U(0x0B0)
#define BSEC_SCRATCH_OFF		U(0x0B4)
#define BSEC_OTP_DATA_OFF		U(0x200)
#define BSEC_IPHW_CFG_OFF		U(0xFF0)
#define BSEC_IPVR_OFF			U(0xFF4)
#define BSEC_IP_ID_OFF			U(0xFF8)
#define BSEC_IP_MAGIC_ID_OFF		U(0xFFC)

/* BSEC_CONFIGURATION Register */
#define BSEC_CONF_POWER_UP_MASK		BIT(0)
#define BSEC_CONF_POWER_UP_SHIFT	U(0)
#define BSEC_CONF_FRQ_MASK		GENMASK_32(2, 1)
#define BSEC_CONF_FRQ_SHIFT		U(1)
#define BSEC_CONF_PRG_WIDTH_MASK	GENMASK_32(6, 3)
#define BSEC_CONF_PRG_WIDTH_SHIFT	U(3)
#define BSEC_CONF_TREAD_MASK		GENMASK_32(8, 7)
#define BSEC_CONF_TREAD_SHIFT		U(7)

/* BSEC_CONTROL Register */
#define BSEC_READ			U(0x000)
#define BSEC_WRITE			U(0x100)
#define BSEC_LOCK			U(0x200)

/* BSEC_STATUS Register */
#define BSEC_MODE_SECURED		BIT(0)
#define BSEC_MODE_INVALID		BIT(2)
#define BSEC_MODE_BUSY			BIT(3)
#define BSEC_MODE_PROGFAIL		BIT(4)
#define BSEC_MODE_PWR			BIT(5)
#define BSEC_MODE_CLOSED		BIT(8)

/* BSEC_DEBUG bitfields */
#ifdef CFG_STM32MP13
#define BSEC_DEN_ALL_MSK		(GENMASK_32(11, 10) | GENMASK_32(8, 1))
#endif
#ifdef CFG_STM32MP15
#define BSEC_DEN_ALL_MSK		GENMASK_32(11, 1)
#endif

/*
 * OTP Lock services definition
 * Value must corresponding to the bit position in the register
 */
#define BSEC_LOCK_UPPER_OTP		U(0x00)
#define BSEC_LOCK_DEBUG			U(0x02)
#define BSEC_LOCK_PROGRAM		U(0x04)

/* Timeout when polling on status */
#define BSEC_TIMEOUT_US			U(10000)

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

static bool state_is_invalid_mode(void)
{
	return bsec_status() & BSEC_MODE_INVALID;
}

static bool state_is_secured_mode(void)
{
	return bsec_status() & BSEC_MODE_SECURED;
}

static bool state_is_closed_mode(void)
{
	uint32_t otp_cfg = 0;
	uint32_t close_mode = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t __maybe_unused sz = 0;
	uint8_t __maybe_unused offset = 0;

	if (IS_ENABLED(CFG_STM32MP13))
		return bsec_status() & BSEC_MODE_CLOSED;

	res = stm32_bsec_find_otp_in_nvmem_layout("cfg0_otp", &otp_cfg,
						  &offset, &sz);
	if (res || sz != 8 || offset)
		panic("CFG0 OTP not found or invalid");

	if (stm32_bsec_read_otp(&close_mode, otp_cfg))
		panic("Unable to read OTP");

	return close_mode & CFG0_OTP_CLOSED_DEVICE;
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
	uint64_t timeout_ref = 0;

	io_mask32(bsec_base() + BSEC_OTP_CONF_OFF, BSEC_CONF_POWER_UP_MASK,
		  BSEC_CONF_POWER_UP_MASK);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (bsec_status() & BSEC_MODE_PWR)
			break;

	if (bsec_status() & BSEC_MODE_PWR)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}

static TEE_Result power_down_safmem(void)
{
	uint64_t timeout_ref = 0;

	io_mask32(bsec_base() + BSEC_OTP_CONF_OFF, 0, BSEC_CONF_POWER_UP_MASK);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_PWR))
			break;

	if (!(bsec_status() & BSEC_MODE_PWR))
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

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();

	result = power_up_safmem();
	if (result)
		goto out;

	io_write32(bsec_base() + BSEC_OTP_CTRL_OFF, otp_id | BSEC_READ);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_BUSY))
			break;

	if (bsec_status() & BSEC_MODE_BUSY)
		result = TEE_ERROR_BUSY;
	else
		result = check_no_error(otp_id, true /* check-disturbed */);

	power_down_safmem();

out:
	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_read_otp(uint32_t *value, uint32_t otp_id)
{
	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

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

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

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

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();

	result = power_up_safmem();
	if (result)
		goto out;

	io_write32(bsec_base() + BSEC_OTP_WRDATA_OFF, value);
	io_write32(bsec_base() + BSEC_OTP_CTRL_OFF, otp_id | BSEC_WRITE);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_BUSY))
			break;

	if (bsec_status() & BSEC_MODE_BUSY)
		result = TEE_ERROR_BUSY;
	else if (bsec_status() & BSEC_MODE_PROGFAIL)
		result = TEE_ERROR_BAD_PARAMETERS;
	else
		result = check_no_error(otp_id, true /* check-disturbed */);

	power_down_safmem();

out:
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
	uint64_t timeout_ref = 0;
	uint32_t upper_base = otp_upper_base();

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * 2 bits per words for lower OTPs: 2:1 Redundancy
	 * 1 bit per word for upper OTPs : ECC support
	 * e.g with 32 lower and 64 upper OTPs:
	 * OTP word to be    ADDR[6:0]   WRDATA[31:0]
	 *     locked
	 *       0             0x00      0x0000 0003
	 *       1             0x00      0x0000 000C
	 *      ...             ...              ...
	 *       7             0x00      0x0000 C000
	 *       8             0x01      0x0000 0003
	 *      ...             ...              ...
	 *      31             0x03      0x0000 C000
	 *      32             0x04      0x0000 0001
	 *      33             0x04      0x0000 0002
	 *      95             0x07      0x0000 8000
	 */
	if (otp_id < upper_base) {
		addr = otp_id / 8U;
		data = DATA_LOWER_OTP_PERLOCK_BIT << ((otp_id * 2U) & 0xF);
	} else {
		addr = upper_base / 8U + (otp_id - upper_base) / 16U;
		data = DATA_UPPER_OTP_PERLOCK_BIT << (otp_id & 0xF);
	}

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();

	result = power_up_safmem();
	if (result)
		goto out;

	io_write32(base + BSEC_OTP_WRDATA_OFF, data);
	io_write32(base + BSEC_OTP_CTRL_OFF, addr | BSEC_WRITE | BSEC_LOCK);

	timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_status() & BSEC_MODE_BUSY))
			break;

	if (bsec_status() & BSEC_MODE_BUSY)
		result = TEE_ERROR_BUSY;
	else if (bsec_status() & BSEC_MODE_PROGFAIL)
		result = TEE_ERROR_BAD_PARAMETERS;
	else
		result = check_no_error(otp_id, false /* not-disturbed */);

#ifdef CFG_STM32MP13
	io_write32(base + BSEC_OTP_CTRL_OFF, addr | BSEC_READ | BSEC_LOCK);
#endif

	power_down_safmem();

out:
	bsec_unlock(exceptions);

	return result;
}
#endif /*CFG_STM32_BSEC_WRITE*/

TEE_Result stm32_bsec_write_debug_conf(uint32_t value)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;

	assert(!(value & ~BSEC_DEN_ALL_MSK));

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();

	io_clrsetbits32(bsec_base() + BSEC_DEN_OFF, BSEC_DEN_ALL_MSK, value);

	if (stm32_bsec_read_debug_conf() == value)
		result = TEE_SUCCESS;

	bsec_unlock(exceptions);

	return result;
}

uint32_t stm32_bsec_read_debug_conf(void)
{
	return io_read32(bsec_base() + BSEC_DEN_OFF) & BSEC_DEN_ALL_MSK;
}

static TEE_Result set_bsec_lock(uint32_t otp_id, size_t lock_offset)
{
	uint32_t bank = otp_bank_offset(otp_id);
	uint32_t otp_mask = BIT(otp_id & BSEC_OTP_MASK);
	vaddr_t lock_addr = bsec_base() + bank + lock_offset;
	uint32_t exceptions = 0;

	if (otp_id > STM32MP1_OTP_MAX_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

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

	if (state_is_invalid_mode())
		return TEE_ERROR_SECURITY;

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

static size_t nsec_access_array_size(void)
{
	size_t upper_count = otp_max_id() - otp_upper_base() + 1;

	return ROUNDUP_DIV(upper_count, BSEC_BITS_PER_WORD);
}

static bool nsec_access_granted(unsigned int index)
{
	uint32_t *array = bsec_dev.nsec_access;

	return array &&
	       (index / BSEC_BITS_PER_WORD) < nsec_access_array_size() &&
	       array[index / BSEC_BITS_PER_WORD] &
	       BIT(index % BSEC_BITS_PER_WORD);
}

bool stm32_bsec_can_access_otp(uint32_t otp_id)
{
	return (otp_id <= otp_max_id()) && !state_is_invalid_mode();
}

bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id)
{
	return otp_id < otp_upper_base() ||
	       nsec_access_granted(otp_id - otp_upper_base());
}

/*
 * struct nvmem_layout - NVMEM cell description
 * @name: Name of the nvmem node in the DT
 * @otp_id: BSEC base index for the OTP words
 * @bit_offset: Bit offset in the OTP word
 * @bit_len: Bit size of the OTP word
 * @phandle: Associated phandle in embedded DTB
 */
struct nvmem_layout {
	char *name;
	uint32_t otp_id;
	uint8_t bit_offset;
	size_t bit_len;
	uint32_t phandle;
};

static struct nvmem_layout *nvmem_layout;
static size_t nvmem_layout_count;

static TEE_Result stm32_bsec_otp_setting(size_t i,
					 uint32_t *otp_id,
					 uint8_t *otp_bit_offset,
					 size_t *otp_bit_len)
{
	if (otp_id)
		*otp_id = nvmem_layout[i].otp_id;

	if (otp_bit_offset)
		*otp_bit_offset = nvmem_layout[i].bit_offset;

	if (otp_bit_len)
		*otp_bit_len = nvmem_layout[i].bit_len;

	DMSG("nvmem[%zu] = %s at BSEC word %" PRIu32 " bits [%" PRIu8 " %zu]",
	     i, nvmem_layout[i].name, nvmem_layout[i].otp_id,
	     nvmem_layout[i].bit_offset, nvmem_layout[i].bit_len);

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_find_otp_in_nvmem_layout(const char *name,
					       uint32_t *otp_id,
					       uint8_t *otp_bit_offset,
					       size_t *otp_bit_len)
{
	size_t i = 0;

	if (!name)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < nvmem_layout_count; i++) {
		if (!nvmem_layout[i].name || strcmp(name, nvmem_layout[i].name))
			continue;

		return stm32_bsec_otp_setting(i, otp_id, otp_bit_offset,
					      otp_bit_len);
	}

	DMSG("nvmem %s failed", name);

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result stm32_bsec_find_otp_by_phandle(const uint32_t phandle,
					  uint32_t *otp_id,
					  uint8_t *otp_bit_offset,
					  size_t *otp_bit_len)
{
	size_t i = 0;

	if (!phandle)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < nvmem_layout_count; i++) {
		if (nvmem_layout[i].phandle != phandle)
			continue;

		return stm32_bsec_otp_setting(i, otp_id, otp_bit_offset,
					      otp_bit_len);
	}

	DMSG("nvmem %u not found", phandle);

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result stm32_bsec_get_state(enum stm32_bsec_sec_state *state)
{
	if (!state)
		return TEE_ERROR_BAD_PARAMETERS;

	if (state_is_invalid_mode() || !state_is_secured_mode()) {
		*state = BSEC_STATE_INVALID;
	} else {
		if (state_is_closed_mode())
			*state = BSEC_STATE_SEC_CLOSED;
		else
			*state = BSEC_STATE_SEC_OPEN;
	}

	return TEE_SUCCESS;
}

static void enable_nsec_access(unsigned int otp_id)
{
	unsigned int idx = (otp_id - otp_upper_base()) / BSEC_BITS_PER_WORD;

	if (otp_id < otp_upper_base())
		return;

	if (otp_id > otp_max_id() || stm32_bsec_shadow_register(otp_id))
		panic();

	bsec_dev.nsec_access[idx] |= BIT(otp_id % BSEC_BITS_PER_WORD);
}

static void bsec_dt_otp_nsec_access(void *fdt, int bsec_node)
{
	int bsec_subnode = 0;

	bsec_dev.nsec_access = calloc(nsec_access_array_size(),
				      sizeof(*bsec_dev.nsec_access));
	if (!bsec_dev.nsec_access)
		panic();

	fdt_for_each_subnode(bsec_subnode, fdt, bsec_node) {
		unsigned int reg_offset = 0;
		unsigned int reg_size = 0;
		unsigned int otp_id = 0;
		unsigned int i = 0;
		size_t size = 0;

		reg_offset = fdt_reg_base_address(fdt, bsec_subnode);
		reg_size = fdt_reg_size(fdt, bsec_subnode);

		assert(reg_offset != DT_INFO_INVALID_REG &&
		       reg_size != DT_INFO_INVALID_REG_SIZE);

		otp_id = reg_offset / sizeof(uint32_t);

		if (otp_id < STM32MP1_UPPER_OTP_START) {
			unsigned int otp_end =
				ROUNDUP_DIV(reg_offset + reg_size,
					    sizeof(uint32_t));

			if (otp_end > STM32MP1_UPPER_OTP_START) {
				/*
				 * OTP crosses Lower/Upper boundary, consider
				 * only the upper part.
				 */
				otp_id = STM32MP1_UPPER_OTP_START;
				reg_size -= (STM32MP1_UPPER_OTP_START *
					     sizeof(uint32_t)) - reg_offset;
				reg_offset = STM32MP1_UPPER_OTP_START *
					     sizeof(uint32_t);

				DMSG("OTP crosses Lower/Upper boundary");
			} else {
				continue;
			}
		}

		/* Handle different kinds of non-secure accesses */
		if (fdt_getprop(fdt, bsec_subnode,
				"st,non-secure-otp-provisioning", NULL)) {
			bool locked = false;
			bool locked_2 = false;

			/* Check if write of OTP is locked */
			if (stm32_bsec_read_permanent_lock(otp_id, &locked))
				panic("Cannot read permanent lock");

			/*
			 * Check if fuses of the subnode
			 * have the same lock status
			 */
			for (i = 1; i < (reg_size / sizeof(uint32_t)); i++) {
				if (stm32_bsec_read_permanent_lock(otp_id + i,
								   &locked_2))
					panic("Cannot read permanent lock");

				if (locked != locked_2) {
					EMSG("Inconsistent status OTP ID %u",
					     otp_id + i);
					locked = true;
				}
			}

			if (locked) {
				DMSG("BSEC: OTP locked");
				continue;
			}
		} else if (!fdt_getprop(fdt, bsec_subnode, "st,non-secure-otp",
					NULL)) {
			continue;
		}

		if ((reg_offset % sizeof(uint32_t)) ||
		    (reg_size % sizeof(uint32_t)))
			panic("Unaligned non-secure OTP");

		size = reg_size / sizeof(uint32_t);

		if (otp_id + size > OTP_MAX_SIZE)
			panic("OTP range oversized");

		for (i = otp_id; i < otp_id + size; i++)
			enable_nsec_access(i);
	}
}

static void save_dt_nvmem_layout(void *fdt, int bsec_node)
{
	int cell_max = 0;
	int cell_cnt = 0;
	int node = 0;

	fdt_for_each_subnode(node, fdt, bsec_node)
		cell_max++;
	if (!cell_max)
		return;

	nvmem_layout = calloc(cell_max, sizeof(*nvmem_layout));
	if (!nvmem_layout)
		panic();

	fdt_for_each_subnode(node, fdt, bsec_node) {
		unsigned int reg_offset = 0;
		unsigned int reg_length = 0;
		const char *string = NULL;
		const char *s = NULL;
		int len = 0;
		struct nvmem_layout *layout_cell = &nvmem_layout[cell_cnt];
		uint32_t bits[2] = { };

		string = fdt_get_name(fdt, node, &len);
		if (!string || !len)
			continue;

		layout_cell->phandle = fdt_get_phandle(fdt, node);
		assert(layout_cell->phandle != (uint32_t)-1);

		reg_offset = fdt_reg_base_address(fdt, node);
		reg_length = fdt_reg_size(fdt, node);

		if (reg_offset == DT_INFO_INVALID_REG ||
		    reg_length == DT_INFO_INVALID_REG_SIZE) {
			DMSG("Malformed nvmem %s: ignored", string);
			continue;
		}

		layout_cell->otp_id = reg_offset / sizeof(uint32_t);
		layout_cell->bit_offset = (reg_offset % sizeof(uint32_t)) *
					  CHAR_BIT;
		layout_cell->bit_len = reg_length * CHAR_BIT;

		if (!fdt_read_uint32_array(fdt, node, "bits", bits, 2)) {
			layout_cell->bit_offset += bits[0];
			layout_cell->bit_len = bits[1];
		}

		s = strchr(string, '@');
		if (s)
			len = s - string;

		layout_cell->name = strndup(string, len);
		if (!layout_cell->name)
			panic();
		cell_cnt++;
		DMSG("nvmem[%d] = %s at BSEC word %" PRIu32
		     " bits [%" PRIu8 " %zu]",
		     cell_cnt, layout_cell->name, layout_cell->otp_id,
		     layout_cell->bit_offset, layout_cell->bit_len);
	}

	if (cell_cnt != cell_max) {
		nvmem_layout = realloc(nvmem_layout,
				       cell_cnt * sizeof(*nvmem_layout));
		if (!nvmem_layout)
			panic();
	}

	nvmem_layout_count = cell_cnt;
}

static void initialize_bsec_from_dt(void)
{
	void *fdt = NULL;
	int node = 0;
	struct dt_node_info bsec_info = { };

	fdt = get_embedded_dt();
	node = fdt_node_offset_by_compatible(fdt, 0, DT_BSEC_COMPAT);
	if (node < 0)
		panic();

	fdt_fill_device_info(fdt, &bsec_info, node);

	if (bsec_info.reg != bsec_dev.base.pa ||
	    !(bsec_info.status & DT_STATUS_OK_SEC))
		panic();

	bsec_dt_otp_nsec_access(fdt, node);

	save_dt_nvmem_layout(fdt, node);
}

static TEE_Result bsec_pm(enum pm_op op, uint32_t pm_hint __unused,
			  const struct pm_callback_handle *hdl __unused)
{
	static uint32_t debug_conf;

	assert(op == PM_OP_SUSPEND || op == PM_OP_RESUME);

	if (op == PM_OP_SUSPEND)
		debug_conf = stm32_bsec_read_debug_conf();
	else
		stm32_bsec_write_debug_conf(debug_conf);

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(bsec_pm);

static TEE_Result initialize_bsec(void)
{
	struct stm32_bsec_static_cfg cfg = { };

	stm32mp_get_bsec_static_cfg(&cfg);

	bsec_dev.base.pa = cfg.base;
	bsec_dev.upper_base = cfg.upper_start;
	bsec_dev.max_id = cfg.max_id;

	if (state_is_invalid_mode())
		panic();

	initialize_bsec_from_dt();

	register_pm_core_service_cb(bsec_pm, NULL, "stm32_bsec");

	return TEE_SUCCESS;
}

early_init(initialize_bsec);
