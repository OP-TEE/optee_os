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

#ifndef TEE_TA_H
#define TEE_TA_H

#include <stdint.h>
#include <tee_api_types.h>

#define TA_HASH_SIZE 32
#define TA_UUID_CLOCK_SIZE 8
#define TA_SIGNATURE_SIZE 264

#define TA_HEAD_FLAG_MASK 0xFFF00000UL
#define TA_HEAD_GOT_MASK  0xFFFFUL

/* Trusted Application header */
typedef struct {
	TEE_UUID uuid;
	uint32_t nbr_func;
	uint32_t ro_size;
	uint32_t rw_size;
	uint32_t zi_size;
	uint32_t rel_dyn_got_size;
	uint32_t hash_type;
	/* uint32_t prop_tracelevel; */
} ta_head_t;

struct ta_rel_dyn {
	uint32_t addr;
	uint32_t info;
};

/*-----------------------------------------------------------------------------
   signed header
   ta_head_t
   ta_func_head_t (1)
   ta_func_head_t (2)
   ...
   ta_func_head_t (N) N = ta_head(_t).nbr_func
   func_1
   func_1
   ...
   func_N
   GOT
   find_service_addr
   hash_1
   hash_2
   ...
   hash_M
 *---------------------------------------------------------------------------*/

#endif
