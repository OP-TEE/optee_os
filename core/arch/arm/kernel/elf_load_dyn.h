/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef _ELF_LOAD_DYN_H_
#define _ELF_LOAD_DYN_H_

#include <compiler.h>
#include <speculation_barrier.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <trace.h>
#include "elf_load_private.h"
#include "elf32.h"

#ifdef CFG_TA_DYNLINK

TEE_Result e32_process_dyn_rel(struct elf_load_state *state, Elf32_Rel *rel,
			       Elf32_Addr *where);

TEE_Result elf_get_needed(struct elf_load_state *state, vaddr_t vabase,
			  char ***needed, size_t *num_needed);

TEE_Result elf_resolve_symbol(struct elf_load_state *state,
			      const char *name, uintptr_t *val);

#else

static inline TEE_Result e32_process_dyn_rel(
		struct elf_load_state *state __unused,
		Elf32_Rel *rel __unused,
		Elf32_Addr *where __unused)
{
	EMSG("Unsupported relocation type %d", ELF32_R_TYPE(rel->r_info));
	return TEE_ERROR_BAD_FORMAT;
}

static inline TEE_Result elf_get_needed(struct elf_load_state *state __unused,
					vaddr_t vabase __unused,
					char ***needed __unused,
					size_t *num_needed __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result elf_resolve_symbol(
		struct elf_load_state *state __unused,
		const char *name __unused, uintptr_t *val __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#endif

#endif /* _ELF_LOAD_DYN_H_ */
