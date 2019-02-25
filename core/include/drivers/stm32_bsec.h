/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 */

#ifndef __STM32_BSEC_H
#define __STM32_BSEC_H

#include <stdint.h>
#include <tee_api.h>

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
TEE_Result stm32_bsec_program_otp(uint32_t value, uint32_t otp_id);

/*
 * Permanent lock of OTP in SAFMEM
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id);

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
 * @value: Value to write in the register, must be non null
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_write_sr_lock(uint32_t otp_id, uint32_t value);

/*
 * Read shadow-read lock
 * @otp_id: OTP number
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_read_sr_lock(uint32_t otp_id);

/*
 * Write shadow-write lock
 * @otp_id: OTP number
 * @value: Value to write in the register, must be non null
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_write_sw_lock(uint32_t otp_id, uint32_t value);

/*
 * Read shadow-write lock
 * @otp_id: OTP number
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_read_sw_lock(uint32_t otp_id);

/*
 * Write shadow-program lock
 * @otp_id: OTP number
 * @value: Value to write in the register, must be non null
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_write_sp_lock(uint32_t otp_id, uint32_t value);

/*
 * Read shadow-program lock
 * @otp_id: OTP number
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_read_sp_lock(uint32_t otp_id);

/*
 * Read permanent lock status
 * @otp_id: OTP number
 * Return true if OTP is locked, else false
 */
bool stm32_bsec_wr_lock(uint32_t otp_id);

/*
 * Lock Upper OTP or Global programming or debug enable
 * @service: Service to lock, see header file
 * @value: Value to write must always set to 1 (only use for debug purpose)
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_otp_lock(uint32_t service, uint32_t value);

/*
 * Return true if non-secure world is allowed to read the target OTP
 * @otp_id: OTP number
 */
bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id);

#endif /*__STM32_BSEC_H*/
