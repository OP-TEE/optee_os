/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef LDELF_ASAN_H
#define LDELF_ASAN_H

#include <asan.h>
#include <tee_api_defines.h>

#ifdef CFG_CORE_SANITIZE_KADDRESS

/* Provided by the linker script  */
extern const vaddr_t __init_array_start;
extern const vaddr_t __init_array_end;
extern char __end[], __text_start[];

TEE_Result asan_init_ldelf(void);
#else
static inline TEE_Result asan_init_ldelf(void)
{
	return TEE_SUCCESS;
}
#endif

#endif /*LDELF_ASAN_H*/

