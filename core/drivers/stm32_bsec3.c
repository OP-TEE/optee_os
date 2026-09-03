// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026 Mateusz Nowicki <mateusz.nowicki@posteo.net>
 */
#include <assert.h>
#include <drivers/stm32_bsec.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

/* BSEC register offsets */
#define BSEC_FVR(i)             (U(0x000) + 4U * (i))
#define BSEC_SPLOCK(i)          (U(0x800) + 4U * (i))
#define BSEC_SWLOCK(i)          (U(0x840) + 4U * (i))
#define BSEC_SRLOCK(i)          (U(0x880) + 4U * (i))
#define BSEC_OTPVLDR(i)         (U(0x8C0) + 4U * (i))
#define BSEC_SFSR(i)            (U(0x940) + 4U * (i))
#define BSEC_OTPCR              U(0xC04)
#define BSEC_WDR                U(0xC08)
#define BSEC_SCRATCHR(i)        (U(0xE00) + 4U * (i))
#define BSEC_LOCKR              U(0xE10)
#define BSEC_JTAGINR            U(0xE14)
#define BSEC_JTAGOUTR           U(0xE18)
#define BSEC_DENR               U(0xE20)
#define BSEC_UNMAPR             U(0xE24)
#define BSEC_SR                 U(0xE40)
#define BSEC_OTPSR              U(0xE44)
#define BSEC_WOSCR(i)           (U(0xF40) + 4U * (i))
#define BSEC_HRCR               U(0xFE8)
#define BSEC_WRCR               U(0xFEC)
#define BSEC_VERR               U(0xFF4)
#define BSEC_IPIDR              U(0xFF8)
#define BSEC_SIDR               U(0xFFC)

/* BSEC LOCKR register fields */
#define BSEC_LOCKR_GWLOCK	BIT(0)
#define BSEC_LOCKR_DENLOCK	BIT(1)
#define BSEC_LOCKR_HKLOCK	BIT(2)

/* BSEC SR register fields */
#define BSEC_SR_HVALID		BIT(1)
#define BSEC_SR_NVSTATE_MASK	GENMASK_32(31, 26)
#define BSEC_SR_NVSTATE_SHIFT	U(26)
#define BSEC_SR_NVSTATE_CLOSED	U(0x0D)

/* BSEC_OTPSR register fields */
#define BSEC_OTPSR_BUSY         BIT(0)
#define BSEC_OTPSR_INIT_DONE    BIT(1)
#define BSEC_OTPSR_HIDEUP       BIT(2)
#define BSEC_OTPSR_OTPNVIR      BIT(4)
#define BSEC_OTPSR_OTPERR       BIT(5)
#define BSEC_OTPSR_OTPSEC       BIT(6)
#define BSEC_OTPSR_PROGFAIL     BIT(16)
#define BSEC_OTPSR_DISTURBF     BIT(17)
#define BSEC_OTPSR_DEDF         BIT(18)
#define BSEC_OTPSR_SECF         BIT(19)
#define BSEC_OTPSR_PPLF         BIT(20)
#define BSEC_OTPSR_PPLMF        BIT(21)
#define BSEC_OTPSR_AMEF         BIT(22)

#define BSEC_OTP_MASK           GENMASK_32(4, 0)
#define BSEC_OTP_BANK_SHIFT     U(5)

#define OTP_BOOTROM_CONFIG_9	U(18)
#define OTP_SECURE_BOOT_MASK	GENMASK_32(3, 0)
#define OTP_SECURE_BOOT_SHIFT	U(0)

/* Timeout when polling on status */
#define BSEC_TIMEOUT_US		U(10000)

#define BSEC_MAX_RETRY		U(3)

#define BSEC_SIZE		U(0x1000)

struct bsec_dev {
	struct io_pa_va base;
	unsigned int upper_base;
	unsigned int max_id;
	unsigned int lock;
};

/* Only 1 instance of BSEC is expected per platform */
static struct bsec_dev bsec_dev = {
	.lock = SPINLOCK_UNLOCK
};

static inline uint32_t field_get(uint32_t reg, uint32_t mask, uint32_t shift)
{
	return (reg & mask) >> shift;
}

static inline uint32_t bsec_lock(void)
{
	return may_spin_lock(&bsec_dev.lock);
}

static inline void bsec_unlock(uint32_t exceptions)
{
	may_spin_unlock(&bsec_dev.lock, exceptions);
}

static inline vaddr_t bsec_base(void)
{
	return io_pa_or_va_secure(&bsec_dev.base, BSEC_SIZE);
}

static inline uint32_t otp_upper_base(void)
{
	return bsec_dev.upper_base;
}

static inline uint32_t otp_max_id(void)
{
	return bsec_dev.max_id;
}

static inline uint32_t otp_bank_offset(uint32_t otp_id)
{
	return ((otp_id & ~BSEC_OTP_MASK) >> BSEC_OTP_BANK_SHIFT);
}

static inline uint32_t otp_bit(uint32_t otp_id)
{
	return BIT(otp_id & BSEC_OTP_MASK);
}

static inline uint32_t bsec_get_otpsr(void)
{
	return io_read32(bsec_base() + BSEC_OTPSR);
}

static inline uint32_t bsec_get_sr(void)
{
	return io_read32(bsec_base() + BSEC_SR);
}

static inline bool is_bsec_write_locked(void)
{
	return (io_read32(bsec_base() + BSEC_LOCKR) & BSEC_LOCKR_GWLOCK);
}

static inline bool are_upper_otps_blocked(void)
{
	return (bsec_get_otpsr() & BSEC_OTPSR_HIDEUP);
}

static inline bool is_global_otp_error(void)
{
	return bsec_get_otpsr() & BSEC_OTPSR_OTPERR;
}

static inline bool is_global_correctable_otp_error(void)
{
	return bsec_get_otpsr() & BSEC_OTPSR_OTPSEC;
}

static inline bool is_otp_init_done(void)
{
	return bsec_get_otpsr() & BSEC_OTPSR_INIT_DONE;
}

static inline bool is_fuse_shadowed(uint32_t otp_id)
{
	const uint32_t bank = otp_bank_offset(otp_id);
	const uint32_t mask = otp_bit(otp_id);

	return (io_read32(bsec_base() + BSEC_SFSR(bank)) & mask);
}

static inline bool is_shadow_valid(uint32_t otp_id)
{
	const uint32_t bank = otp_bank_offset(otp_id);
	const uint32_t mask = otp_bit(otp_id);

	return (io_read32(bsec_base() + BSEC_OTPVLDR(bank)) & mask);
}

static inline bool is_shadow_update_locked(uint32_t otp_id)
{
	const uint32_t bank = otp_bank_offset(otp_id);
	const uint32_t mask = otp_bit(otp_id);

	return (io_read32(bsec_base() + BSEC_SRLOCK(bank)) & mask);
}

static TEE_Result read_bsec_lock(uint32_t otp_id, bool *locked,
				 uint32_t lock_offset)
{
	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (!locked)
		return TEE_ERROR_BAD_PARAMETERS;

	*locked = io_read32(bsec_base() + lock_offset) & otp_bit(otp_id);
	return TEE_SUCCESS;
}

static bool is_invalid_mode(void)
{
	const uint32_t nvstate = field_get(bsec_get_sr(), BSEC_SR_NVSTATE_MASK,
					 BSEC_SR_NVSTATE_SHIFT);

	return nvstate != BSEC_SR_NVSTATE_CLOSED;
}

static TEE_Result poll_busy_status_and_check_read_errors(bool *fatal_detected)
{
	uint64_t timeout = timeout_init_us(BSEC_TIMEOUT_US);
	uint32_t otpsr = 0;

	assert(fatal_detected);

	while (!timeout_elapsed(timeout)) {
		otpsr = bsec_get_otpsr();
		if (!(otpsr & BSEC_OTPSR_BUSY))
			break;
	}

	if (otpsr & BSEC_OTPSR_BUSY) {
		DMSG("BSEC: OTP is still busy");
		*fatal_detected = true;
		return TEE_ERROR_BUSY;
	}

	if (otpsr & BSEC_OTPSR_DISTURBF) {
		DMSG("BSEC: Integrity of the fuse value is not guaranteed");
		return TEE_ERROR_GENERIC;
	}

	if (otpsr & BSEC_OTPSR_DEDF) {
		DMSG("BSEC: Double error detected. Fuse word is corrupted");
		return TEE_ERROR_GENERIC;
	}

	if (otpsr & BSEC_OTPSR_PPLF)
		DMSG("BSEC: Permanent programming lock detected");

	if (otpsr & BSEC_OTPSR_PPLMF) {
		DMSG("BSEC: Permanent programming lock mismatch");
		*fatal_detected = true;
		return TEE_ERROR_GENERIC;
	}

	if (otpsr & BSEC_OTPSR_AMEF) {
		DMSG("BSEC: Fuse address mismatch");
		return TEE_ERROR_GENERIC;
	}

	if (otpsr & BSEC_OTPSR_SECF)
		DMSG("BSEC: Single bit error correction");

	return TEE_SUCCESS;
}

static TEE_Result shadow_otp(uint32_t otp_id)
{
	uint32_t i = 0U;
	TEE_Result result = TEE_SUCCESS;
	bool fatal = false;

	if (is_bsec_write_locked() || is_shadow_update_locked(otp_id))
		return TEE_ERROR_ACCESS_DENIED;

	for (i = 0U; i < BSEC_MAX_RETRY; ++i) {
		io_write32(bsec_base() + BSEC_OTPCR, otp_id);
		result = poll_busy_status_and_check_read_errors(&fatal);
		if (!result || fatal)
			break;
	}
	return result;
}

static void check_post_reset_status(void)
{
	if (!is_otp_init_done())
		panic("BSEC3 is not ready");

	if (is_invalid_mode())
		panic("BSEC3 is in invalid mode, OTP can't be trusted");

	if (is_global_otp_error())
		panic("BSEC got global error during OTP auto-load");

	if (is_global_correctable_otp_error())
		DMSG("BSEC single error corrected during OTP auto-load");

	if (are_upper_otps_blocked())
		bsec_dev.max_id = bsec_dev.upper_base - 1;
}

TEE_Result stm32_bsec_read_sr_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked,
				  BSEC_SRLOCK(otp_bank_offset(otp_id)));
}

TEE_Result stm32_bsec_read_sw_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked,
				  BSEC_SWLOCK(otp_bank_offset(otp_id)));
}

TEE_Result stm32_bsec_read_sp_lock(uint32_t otp_id, bool *locked)
{
	return read_bsec_lock(otp_id, locked,
				  BSEC_SPLOCK(otp_bank_offset(otp_id)));
}

bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id)
{
	return otp_id < otp_upper_base();
}

TEE_Result stm32_bsec_write_otp(uint32_t value, uint32_t otp_id)
{
	(void)value;
	(void)otp_id;
	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result stm32_bsec_get_state(enum stm32_bsec_sec_state *state)
{
	uint32_t secure_boot = 0;
	TEE_Result result = TEE_SUCCESS;

	if (!state)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_invalid_mode()) {
		*state = BSEC_STATE_INVALID;
		return TEE_SUCCESS;
	}

	result = stm32_bsec_read_otp(&secure_boot, OTP_BOOTROM_CONFIG_9);
	if (result) {
		*state = BSEC_STATE_INVALID;
		return result;
	}

	secure_boot = field_get(secure_boot, OTP_SECURE_BOOT_MASK,
				OTP_SECURE_BOOT_SHIFT);
	if (secure_boot)
		*state = BSEC_STATE_SEC_CLOSED;
	else
		*state = BSEC_STATE_SEC_OPEN;

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_read_permanent_lock(uint32_t otp_id, bool *locked)
{
	uint32_t exceptions = 0;
	TEE_Result result = TEE_SUCCESS;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (!locked)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();
	result = shadow_otp(otp_id);
	if (!result)
		*locked = (bsec_get_otpsr() & BSEC_OTPSR_PPLF);

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_shadow_register(uint32_t otp_id)
{
	uint32_t exceptions = 0;
	TEE_Result result = TEE_SUCCESS;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();
	result = shadow_otp(otp_id);
	bsec_unlock(exceptions);
	return result;
}

TEE_Result stm32_bsec_read_otp(uint32_t *value, uint32_t otp_id)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (!value)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();
	if (!is_fuse_shadowed(otp_id)) {
		result = shadow_otp(otp_id);
		if (result)
			goto out;
	} else if (!is_shadow_valid(otp_id)) {
		result = shadow_otp(otp_id);

		/* shadowed word stays readable even when reload is locked */
		if (result && result != TEE_ERROR_ACCESS_DENIED)
			goto out;
	}

	*value = io_read32(bsec_base() + BSEC_FVR(otp_id));
	result = TEE_SUCCESS;

out:
	bsec_unlock(exceptions);
	return result;
}

TEE_Result stm32_bsec_shadow_read_otp(uint32_t *otp_value, uint32_t otp_id)
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exceptions = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (!otp_value)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_invalid_mode())
		return TEE_ERROR_SECURITY;

	exceptions = bsec_lock();
	result = shadow_otp(otp_id);
	if (!result)
		*otp_value = io_read32(bsec_base() + BSEC_FVR(otp_id));

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_set_sw_lock(uint32_t otp_id)
{
	uint32_t exceptions = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();
	io_setbits32(bsec_base() + BSEC_SWLOCK(otp_bank_offset(otp_id)),
		     otp_bit(otp_id));
	bsec_unlock(exceptions);

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_set_sr_lock(uint32_t otp_id)
{
	uint32_t exceptions = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();
	io_setbits32(bsec_base() + BSEC_SRLOCK(otp_bank_offset(otp_id)),
		     otp_bit(otp_id));
	bsec_unlock(exceptions);

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_set_sp_lock(uint32_t otp_id)
{
	uint32_t exceptions = 0;

	if (otp_id > otp_max_id())
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();
	io_setbits32(bsec_base() + BSEC_SPLOCK(otp_bank_offset(otp_id)),
		     otp_bit(otp_id));
	bsec_unlock(exceptions);

	return TEE_SUCCESS;
}

static TEE_Result bsec_pm(enum pm_op op, uint32_t pm_hint,
			  const struct pm_callback_handle *hdl __unused)
{
	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT))
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME)
		check_post_reset_status();

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(bsec_pm);

static TEE_Result initialize_bsec(void)
{
	struct stm32_bsec3_static_cfg cfg = { };

	stm32mp_get_bsec3_static_cfg(&cfg);

	bsec_dev.base.pa = cfg.base;
	bsec_dev.upper_base = cfg.upper_start;
	bsec_dev.max_id = cfg.max_id;

	check_post_reset_status();

	register_pm_core_service_cb(bsec_pm, NULL, "stm32_bsec3");

	return TEE_SUCCESS;
}
early_init(initialize_bsec);
