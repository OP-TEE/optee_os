/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  \file       kta_types.h
 *  \brief      This file contains types related to the secure library API.
 *  @{
 */

#ifndef KTA_TYPES_H
#define KTA_TYPES_H

#include <stdint.h>

/*
 * KTA return value type
 */

/* Return code type */
typedef uint32_t t_kta_return_value;

/*
 * Structure of return type
 *  -----------------------------------------------------------------
 *  | flags |        domain         |             code              |
 *  -----------------------------------------------------------------
 *   31   28 27                   16 15                            0
 */
/* flags: 0x0 = success / 0x8 = failure */

/* Success codes (domain = D, error code =Y) */
/* #define KTA_RET_OK_REASON_X      (0x000Y000X) */
#define KTA_RET_OK          ((t_kta_return_value)0x00000001)
#define KTA_RET_BUSY        ((t_kta_return_value)0x00000003)

/* Failure codes (domain = D, error code =Y) */
/* #define KTA_RET_FAIL_ERROR_X      (0x900Y000X) */
#define KTA_RET_FAIL                   ((t_kta_return_value)0x90000001)
#define KTA_RET_NON_SUPPORTED_APPL     ((t_kta_return_value)0x90000002)
#define KTA_RET_NON_VALID_ADDRESS      ((t_kta_return_value)0x90000003)
#define KTA_RET_MMU_TRANSLATION_FAULT  ((t_kta_return_value)0x90000004)
#define KTA_RET_INVALID_ARGS           ((t_kta_return_value)0x90000005)

typedef struct kta_signed_header {
	uint32_t magic;
	uint16_t size_of_signed_header;
	uint16_t size_of_signature;
	uint32_t sign_hash_type;        /* see t_hash_type */
	uint32_t signature_type;        /* see t_signature_type */
	uint32_t hash_type;	        /* see t_hash_type */
	uint32_t payload_type;	        /* see enum kta_payload_type */
	uint32_t flags;		        /* reserved */
	uint32_t size_of_payload;
	uint32_t sw_vers_nbr;
	uint32_t load_address;
	uint32_t startup_address;
	uint32_t spare;		/* reserved */
} kta_signed_header_t;

#endif /* End of kta_types.h */

/** @} */
