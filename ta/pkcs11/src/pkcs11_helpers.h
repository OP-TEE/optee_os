/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_HELPERS_H
#define PKCS11_HELPERS_H

#include <pkcs11_ta.h>
#include <stdint.h>
#include <stddef.h>

/* Short aliases for return code */
#define PKCS11_OK			PKCS11_CKR_OK
#define PKCS11_ERROR			PKCS11_CKR_GENERAL_ERROR
#define PKCS11_MEMORY			PKCS11_CKR_DEVICE_MEMORY
#define PKCS11_BAD_PARAM		PKCS11_CKR_ARGUMENTS_BAD
#define PKCS11_SHORT_BUFFER		PKCS11_CKR_BUFFER_TOO_SMALL
#define PKCS11_FAILED			PKCS11_CKR_FUNCTION_FAILED
#define PKCS11_NOT_FOUND		PKCS11_RV_NOT_FOUND
#define PKCS11_NOT_IMPLEMENTED		PKCS11_RV_NOT_IMPLEMENTED

/*
 * Convert PKCS11 TA return code into a GPD TEE result ID when matching.
 * If not, return a TEE success (_noerr) or a generic error (_error).
 */
TEE_Result pkcs2tee_noerr(uint32_t rv);
TEE_Result pkcs2tee_error(uint32_t rv);
uint32_t tee2pkcs_error(TEE_Result res);

#if CFG_TEE_TA_LOG_LEVEL > 0
/* Id-to-string conversions only for trace support */
const char *id2str_ta_cmd(uint32_t id);
const char *id2str_rc(uint32_t id);
const char *id2str_proc_flag(uint32_t id);
const char *id2str_slot_flag(uint32_t id);
const char *id2str_token_flag(uint32_t id);
#endif /* CFG_TEE_TA_LOG_LEVEL > 0 */
#endif /*PKCS11_HELPERS_H*/
