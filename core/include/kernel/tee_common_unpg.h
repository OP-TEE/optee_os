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
#ifndef TEE_COMMON_UNPG_H
#define TEE_COMMON_UNPG_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <kernel/kta_types.h>
#include <tee_api_types.h>
#include <mm/tee_mm_def.h>
#include <kernel/tee_misc_unpg.h>

#define TEE_MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

#define TEE_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef uintptr_t tee_paddr_t;
/* Compat */
#define tee_phys_addr_t tee_paddr_t

typedef uintptr_t tee_vaddr_t;
/* Virtual address valid in user mode */
typedef uintptr_t tee_uaddr_t;


#if (CFG_TEE_FW_DEBUG == 0)

#define TEE_ASSERT(expr) \
	do { \
		if (!(expr)) { \
			DMSG("assertion failed"); \
			while (1) \
				; \
		} \
	} while (0)

#else

#define TEE_ASSERT(expr) \
	do { \
		if (!(expr)) { \
			EMSG("assertion '%s' failed at %s:%d (func '%s')", \
				#expr, __FILE__, __LINE__, __func__); \
			while (1) \
				; \
		} \
	} while (0)

#endif

#define TEE_ASSERT_ALIGNMENT(p, type)                       \
		TEE_ASSERT(TEE_ALIGNMENT_IS_OK(p, type))

#ifndef TEE_ALIGNMENT_IS_OK
#ifdef CFG_TC_NO_ALIGNOF
#define TEE_ALIGNMENT_1B_IS_OK(p, type)    (true)
#define TEE_ALIGNMENT_2B_IS_OK(p, type)    ((&(p) & 1 == 0) ? true : false)
#define TEE_ALIGNMENT_4B_IS_OK(p, type)    ((&(p) & 3 == 0) ? true : false)
#define TEE_ALIGNMENT_8B_IS_OK(p, type)    ((&(p) & 7 == 0) ? true : false)
#define TEE_ALIGNMENT_IS_OK(p, type)       TEE_ALIGNMENT_4B_IS_OK(p, type)
#else
#define TEE_ALIGNMENT_1B_IS_OK(p, type)    TEE_ALIGNMENT_WRAP_IS_OK(p, type)
#define TEE_ALIGNMENT_2B_IS_OK(p, type)    TEE_ALIGNMENT_WRAP_IS_OK(p, type)
#define TEE_ALIGNMENT_4B_IS_OK(p, type)    TEE_ALIGNMENT_WRAP_IS_OK(p, type)
#define TEE_ALIGNMENT_8B_IS_OK(p, type)    TEE_ALIGNMENT_WRAP_IS_OK(p, type)
#define TEE_ALIGNMENT_IS_OK(p, type)       TEE_ALIGNMENT_WRAP_IS_OK(p, type)

#define TEE_ALIGNMENT_WRAP_IS_OK(p, type)                        \
		(((uintptr_t)p & (__tee_assert_alignof__(type) - 1)) == 0)

#define __tee_assert_alignof__(type) __alignof__(type)
#endif
#endif

/*-----------------------------------------------------------------------------
 * tee_ta_load_page - Loads a page at address va_addr
 * Parameters:
 * va_addr - The address somewhere in the page to be loaded (in)
 * Returns:
 *           A session handle to the session related to the memory accessed
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
void *tee_ta_load_page(const uint32_t va_addr);

/*-----------------------------------------------------------------------------
 * tee_ta_check_rw - Checks if a page at va_addr contains rw data which should
 * be saved
 * Parameters:
 * va_addr - The address somewhere in the page to be removed (in)
 * session_handle - The session handle of the page
 * Returns:
 *           Returns 1 if the page contains data, 0 otherwise
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
uint32_t tee_ta_check_rw(const uint32_t va_addr, const void *session_handle);

/*-----------------------------------------------------------------------------
 * tee_ta_save_rw removes a page at address va_addr
 * Parameters:
 * va_addr - The address somewhere in the page to be removed (in)
 * session_handle - The session handle of the page
 * Returns:
 *           void
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
void tee_ta_save_rw(const uint32_t va_addr, const void *session_handle);

#endif /* TEE_COMMON_UNPG_H */
