/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __TPM2_H__
#define __TPM2_H__

#include <stdint.h>
#include <types_ext.h>
#include <util.h>

/* TPM2_ST Structure Tags */
#define TPM2_ST_RSP_COMMAND	U(0x00C4)
#define TPM2_ST_NULL		U(0X8000)
#define TPM2_ST_NO_SESSIONS	U(0x8001)
#define TPM2_ST_SESSIONS	U(0x8002)

/* TPM2_SU Constants Shutdown and startup modes */
#define TPM2_SU_CLEAR		U(0x0000)
#define TPM2_SU_STATE		U(0x0001)

/* Command Codes */
#define	TPM2_CC_NV_WRITE	U(0x00000137)
#define	TPM2_CC_SELFTEST	U(0x00000143)
#define TPM2_CC_STARTUP		U(0x00000144)
#define	TPM2_CC_NV_READ		U(0x0000014E)
#define	TPM2_CC_GET_CAPABILITY  U(0x0000017A)
#define	TPM2_CC_PCR_READ	U(0x0000017E)
#define	TPM2_CC_PCR_EXTEND	U(0x00000182)

/*
 * Send a TPM2_Startup command
 *
 * @mode - TPM startup mode
 *	   It is one of TPM2_SU_CLEAR or TPM2_SU_STATE
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_startup(uint16_t mode);

/*
 * Send a TPM2_SelfTest command
 *
 * @full - 1 if full test needs to be performed
 *	   0 if only test of untested functions required
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_selftest(uint8_t full);

#endif	/* __TPM2_H__ */

