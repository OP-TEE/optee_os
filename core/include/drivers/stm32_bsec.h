/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2022, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_BSEC_H
#define __DRIVERS_STM32_BSEC_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api.h>

/* BSEC_DEBUG */
#define BSEC_HDPEN			BIT(4)
#define BSEC_SPIDEN			BIT(5)
#define BSEC_SPINDEN			BIT(6)
#define BSEC_DBGSWGEN			BIT(10)
#define BSEC_DEBUG_ALL			(BSEC_HDPEN | \
					 BSEC_SPIDEN | \
					 BSEC_SPINDEN | \
					 BSEC_DBGSWGEN)

#define BSEC_BITS_PER_WORD		(8U * sizeof(uint32_t))
#define BSEC_BYTES_PER_WORD		sizeof(uint32_t)

/* BSEC different global states */
enum stm32_bsec_sec_state {
	BSEC_STATE_SEC_CLOSED,
	BSEC_STATE_SEC_OPEN,
	BSEC_STATE_INVALID
};

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

/* Return debug configuration read from BSEC */
uint32_t stm32_bsec_read_debug_conf(void);

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
