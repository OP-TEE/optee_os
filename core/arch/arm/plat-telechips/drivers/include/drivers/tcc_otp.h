/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#ifndef __DRIVERS_TCC_OTP_H
#define __DRIVERS_TCC_OTP_H

TEE_Result tcc_otp_read_128(uint32_t offset, uint32_t *buf);
TEE_Result tcc_otp_write_128(uint32_t offset, const uint32_t *buf);

#endif /* __DRIVERS_TCC_OTP_H */
