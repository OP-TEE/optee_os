/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2022, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_BSEC_H
#define __DRIVERS_STM32_BSEC_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api.h>
#include <types_ext.h>

/* Debug permission mask */
/* Cortex A Non-Secure Trace-only */
#define STM32_BSEC_DEBUG_CORTEX_A_NSTO		BIT(0)
/* Cortex A Non-Secure Full-Debug */
#define STM32_BSEC_DEBUG_CORTEX_A_NSFD		BIT(1)
/* Cortex A Secure Trace-only */
#define STM32_BSEC_DEBUG_CORTEX_A_STO		BIT(2)
/* Cortex A Secure Full-Debug */
#define STM32_BSEC_DEBUG_CORTEX_A_SFD		BIT(3)
/* Cortex M Non-Secure Trace-only */
#define STM32_BSEC_DEBUG_CORTEX_M_NSTO		BIT(4)
/* Cortex M Non-Secure Full-Debug */
#define STM32_BSEC_DEBUG_CORTEX_M_NSFD		BIT(5)
/* Cortex M Secure Trace-only */
#define STM32_BSEC_DEBUG_CORTEX_M_STO		BIT(6)
/* Cortex M Secure Full-Debug */
#define STM32_BSEC_DEBUG_CORTEX_M_SFD		BIT(7)
/* Cortex A Minimal Debug HDP level */
#define STM32_BSEC_DEBUG_CORTEX_A_HDPL		BIT(8)
#define STM32_BSEC_DEBUG_CORTEX_A_HDP(lvl) \
	(STM32_BSEC_DEBUG_CORTEX_A_HDPL << (lvl))
/* Cortex M Minimal Debug HDP level */
#define STM32_BSEC_DEBUG_CORTEX_M_HDPL		BIT(12)
#define STM32_BSEC_DEBUG_CORTEX_M_HDP(lvl) \
	(STM32_BSEC_DEBUG_CORTEX_M_HDPL << (lvl))
/* Cortex A Secure Debug Disabled */
#define STM32_BSEC_DEBUG_CORTEX_A_SDDIS		BIT(16)
/* Cortex A Non-Sec Debug Disabled */
#define STM32_BSEC_DEBUG_CORTEX_A_NSDDIS	BIT(17)
/* Cortex M Secure Debug Disabled */
#define STM32_BSEC_DEBUG_CORTEX_M_SDDIS		BIT(18)
/* Cortex M Non-Sec Debug Disabled */
#define STM32_BSEC_DEBUG_CORTEX_M_NSDDIS	BIT(19)
/* Wait for attach at boot time */
#define STM32_BSEC_DEBUG_WAITATTACH		BIT(31)

#define STM32_BSEC_DEBUG_ALL (STM32_BSEC_DEBUG_CORTEX_A_NSFD | \
			      STM32_BSEC_DEBUG_CORTEX_A_SFD | \
			      STM32_BSEC_DEBUG_CORTEX_M_NSFD | \
			      STM32_BSEC_DEBUG_CORTEX_M_SFD | \
			      STM32_BSEC_DEBUG_CORTEX_A_HDP(0) | \
			      STM32_BSEC_DEBUG_CORTEX_M_HDP(0))

#define BSEC_BITS_PER_WORD		(8U * sizeof(uint32_t))
#define BSEC_BYTES_PER_WORD		sizeof(uint32_t)

/* BSEC different global states */
enum stm32_bsec_sec_state {
	BSEC_STATE_SEC_CLOSED,
	BSEC_STATE_SEC_OPEN,
	BSEC_STATE_INVALID
};

/*
 * Structure and API function for BSEC driver to get some platform data.
 *
 * @base: BSEC interface registers physical base address
 * @mirror: BSEC mirror base address
 * @upper_start: Base ID for the BSEC upper words in the platform
 * @max_id: Max value for BSEC word ID for the platform
 */
struct stm32_bsec_static_cfg {
	paddr_t base;
	paddr_t mirror;
	unsigned int upper_start;
	unsigned int max_id;
};

void plat_bsec_get_static_cfg(struct stm32_bsec_static_cfg *cfg);

/*
 * Load OTP from SAFMEM and provide its value
 * @value: Output read value
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_shadow_read_otp(uint32_t *value, uint32_t otp_id);

/*
 * Copy SAFMEM OTP to BSEC data.
 * @otp_id: OTP number.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_shadow_register(uint32_t otp_id);

/*
 * Read an OTP data value
 * @value: Output read value
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_otp(uint32_t *value, uint32_t otp_id);

/*
 * Read a range of OTP data values thanks to the name of the cell
 * @name: Name of the cell describing the OTP range
 * @len : Size of the OTP range to read
 * @values : Output read values
 */
TEE_Result stm32_bsec_read_otp_range_by_name(const char *name,
					     size_t len, uint8_t **values);

/*
 * Write value in BSEC data register
 * @value: Value to write
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_write_otp(uint32_t value, uint32_t otp_id);

/*
 * Program a bit in SAFMEM without BSEC data refresh
 * @value: Value to program.
 * @otp_id: OTP number.
 * Return a TEE_Result compliant return value
 */
#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_program_otp(uint32_t value, uint32_t otp_id);
#else
static inline TEE_Result stm32_bsec_program_otp(uint32_t value __unused,
						uint32_t otp_id __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/*
 * Permanent lock of OTP in SAFMEM
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id);
#else
static inline TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/*
 * Enable/disable debug service
 * @value: Value to write
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_write_debug_conf(uint32_t value);

/*
 * Write shadow-read lock
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_set_sr_lock(uint32_t otp_id);

/*
 * Read shadow-read lock
 * @otp_id: OTP number
 * @locked: (out) true if shadow-read is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_sr_lock(uint32_t otp_id, bool *locked);

/*
 * Write shadow-write lock
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_set_sw_lock(uint32_t otp_id);

/*
 * Read shadow-write lock
 * @otp_id: OTP number
 * @locked: (out) true if shadow-write is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_sw_lock(uint32_t otp_id, bool *locked);

/*
 * Write shadow-program lock
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_set_sp_lock(uint32_t otp_id);

/*
 * Read shadow-program lock
 * @otp_id: OTP number
 * @locked: (out) true if shadow-program is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_sp_lock(uint32_t otp_id, bool *locked);

/*
 * Read permanent lock status
 * @otp_id: OTP number
 * @locked: (out) true if permanent lock is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_permanent_lock(uint32_t otp_id, bool *locked);

/*
 * Return true if OTP can be read, false otherwise
 * @otp_id: OTP number
 */
bool stm32_bsec_can_access_otp(uint32_t otp_id);

/*
 * Return true if non-secure world is allowed to read the target OTP
 * @otp_id: OTP number
 */
bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id);

/*
 * Return true if host-self debug is enabled.
 */
bool stm32_bsec_self_hosted_debug_is_enabled(void);

/*
 * Return true if Hardware Debug Port (HDP) is enabled.
 */
bool stm32_bsec_hdp_is_enabled(void);

/*
 * Return true if coresight peripheral can be used.
 */
bool stm32_bsec_coresight_is_enabled(void);

/*
 * Program BSEC to open DBGMCU_APB_AP (AP0)
 */
void stm32_bsec_mp21_ap0_unlock(void);

/*
 * Find and get OTP location from its name.
 * @name: sub-node name to look up.
 * @otp_id: pointer to output OTP number or NULL.
 * @otp_bit_offset: pointer to output OTP bit offset in the NVMEM cell or NULL.
 * @otp_bit_len: pointer to output OTP length in bits or NULL.
 * Return a TEE_Result compliant status
 */
TEE_Result stm32_bsec_find_otp_in_nvmem_layout(const char *name,
					       uint32_t *otp_id,
					       uint8_t *otp_bit_offset,
					       size_t *otp_bit_len);

/*
 * Find and get OTP location from its phandle.
 * @phandle: node phandle to look up.
 * @otp_id: pointer to read OTP number or NULL.
 * @otp_bit_offset: pointer to read offset in OTP in bits or NULL.
 * @otp_bit_len: pointer to read OTP length in bits or NULL.
 * Return a TEE_Result compliant status
 */
TEE_Result stm32_bsec_find_otp_by_phandle(const uint32_t phandle,
					  uint32_t *otp_id,
					  uint8_t *otp_bit_offset,
					  size_t *otp_bit_len);

/*
 * Get BSEC global sec state.
 * @sec_state: Global BSEC current sec state
 * Return a TEE_Result compliant status
 */
TEE_Result stm32_bsec_get_state(enum stm32_bsec_sec_state *sec_state);

#endif /*__DRIVERS_STM32_BSEC_H*/
