/*
 * Copyright (c) 2014, Linaro Limited
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
#include <types_ext.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>
#include <tee/tee_cryp_provider.h>
#include <stdlib.h>
#include <util.h>
#include <trace.h>
#include "elf_load.h"
#include "elf_common.h"
#include "elf32.h"


#define TEE_TA_STACK_ALIGNMENT   8

static TEE_Result advance_to(struct elf_load_state *state, size_t offs)
{
	TEE_Result res;

	if (offs < state->next_offs)
		return TEE_ERROR_BAD_STATE;
	if (offs == state->next_offs)
		return TEE_SUCCESS;

	if (offs > state->nwdata_len)
		return TEE_ERROR_SECURITY;

	res = crypto_ops.hash.update(state->hash_ctx, state->hash_algo,
			state->nwdata + state->next_offs,
			offs - state->next_offs);
	if (res != TEE_SUCCESS)
		return res;
	state->next_offs = offs;
	return res;
}

static TEE_Result copy_to(struct elf_load_state *state,
			void *dst, size_t dst_size, size_t dst_offs,
			size_t offs, size_t len)
{
	TEE_Result res;

	res = advance_to(state, offs);
	if (res != TEE_SUCCESS)
		return res;
	if (!len)
		return TEE_SUCCESS;

	if (len > dst_size || (len + dst_offs) > dst_size)
		return TEE_ERROR_SECURITY;

	if (!core_is_buffer_inside(state->nwdata + offs, len,
				   state->nwdata, state->nwdata_len))
		return TEE_ERROR_SECURITY;

	memcpy((uint8_t *)dst + dst_offs, state->nwdata + offs, len);
	res = crypto_ops.hash.update(state->hash_ctx, state->hash_algo,
				      (uint8_t *)dst + dst_offs, len);
	if (res != TEE_SUCCESS)
		return res;
	state->next_offs = offs + len;
	return res;
}

static TEE_Result alloc_and_copy_to(void **p, struct elf_load_state *state,
			size_t offs, size_t len)
{
	TEE_Result res;
	void *buf;

	buf = malloc(len);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = copy_to(state, buf, len, 0, offs, len);
	if (res == TEE_SUCCESS)
		*p = buf;
	else
		free(buf);
	return res;
}

static TEE_Result el_process_rel(struct elf_load_state *state __unused,
			Elf32_Shdr *shdr, size_t sidx, vaddr_t vabase)
{
	Elf32_Rel *rel;
	Elf32_Rel *rel_end;

	if (shdr[sidx].sh_entsize != sizeof(Elf32_Rel))
		return TEE_ERROR_BAD_FORMAT;

	rel = (Elf32_Rel *)(vabase + shdr[sidx].sh_addr);
	if (!TEE_ALIGNMENT_IS_OK(rel, Elf32_Rel))
		return TEE_ERROR_BAD_FORMAT;

	rel_end = rel + shdr[sidx].sh_size / sizeof(Elf32_Rel);
	for (; rel < rel_end; rel++) {
		Elf32_Addr *where = (Elf32_Addr *)(vabase + rel->r_offset);

		if (!TEE_ALIGNMENT_IS_OK(where, Elf32_Addr))
			return TEE_ERROR_BAD_FORMAT;

		switch (ELF32_R_TYPE(rel->r_info)) {
		case R_ARM_RELATIVE:
			*where += (Elf32_Addr)vabase;
			break;
		default:
			EMSG("Unknown relocation type %d",
			     ELF32_R_TYPE(rel->r_info));
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	return TEE_SUCCESS;
}


TEE_Result elf_load(struct elf_load_state *state)
{
	TEE_Result res;
	struct tee_ta_param param = { 0 };
	struct ta_head *ta_head = NULL;
	Elf32_Ehdr *ehdr = NULL;
	Elf32_Phdr *phdr = NULL;
	Elf32_Shdr *shdr = NULL;
	uint8_t *dst;
	size_t dst_size;
	size_t n;
	void *p;

	/*
	 * The ELF resides in shared memory, to avoid attacks based on
	 * modifying the ELF while we're parsing it here we only read each
	 * byte from the ELF once. We're also hashing the ELF while reading
	 * so we're limited to only read the ELF sequentially from start to
	 * end.
	 */

	res = alloc_and_copy_to(&p, state, 0, sizeof(Elf32_Ehdr));
	if (res != TEE_SUCCESS)
		return res;
	ehdr = p;

	if (!IS_ELF(*ehdr) || ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE ||
	    ehdr->e_type != ET_DYN || ehdr->e_machine != EM_ARM ||
	    ehdr->e_phentsize != sizeof(Elf32_Phdr) ||
	    ehdr->e_shentsize != sizeof(Elf32_Shdr)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/*
	 * Program headers are supposed to be arranged as:
	 * LOAD [0] : .ta_head ...
	 * ...
	 * LOAD [n]
	 *
	 * .ta_head must be located first in the first program header, which
	 * also has to be of LOAD type.
	 *
	 * A DYNAMIC segment may appear, but is ignored. Any other segment
	 * except LOAD and DYNAMIC will cause an error. All sections not
	 * included by a LOAD segment are ignored.
	 */
	if (ehdr->e_phnum < 1) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	res = alloc_and_copy_to(&p, state, ehdr->e_phoff,
				ehdr->e_phnum * sizeof(Elf32_Phdr));
	if (res != TEE_SUCCESS)
		goto out;
	phdr = p;

	if (phdr[0].p_type != PT_LOAD || phdr[0].p_vaddr != 0) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/*
	 * Allocate physical memory for TA. Find the max address used
	 * by a LOAD type.
	 */
	dst_size = phdr[0].p_vaddr + phdr[0].p_memsz;
	for (n = 1; n < ehdr->e_phnum; n++) {
		if (phdr[n].p_type == PT_LOAD)
			dst_size = phdr[n].p_vaddr + phdr[n].p_memsz;
		else if (phdr[n].p_type != PT_DYNAMIC) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
	}
	state->ctx->mm = tee_mm_alloc(&tee_mm_sec_ddr, dst_size);
	if (!state->ctx->mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Read .ta_head from first segment, make sure the segment is large
	 * enough. We're only interesting in seeing that the
	 * TA_FLAG_EXEC_DDR flag is set. If that's true we set that flag in
	 * the TA context to enable mapping the TA. Later when this
	 * function has returned and the hash has been verified the flags
	 * field will be updated with eventual other flags.
	 */
	if (phdr[0].p_filesz < sizeof(struct ta_head)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	res = alloc_and_copy_to(&p, state, phdr[0].p_offset,
				sizeof(struct ta_head));
	if (res != TEE_SUCCESS)
		goto out;
	ta_head = p;

	/* Currently all TA must execute from DDR */
	if (!(ta_head->flags & TA_FLAG_EXEC_DDR)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	state->ctx->flags = TA_FLAG_EXEC_DDR;

	/* Ensure proper aligment of stack */
	state->ctx->stack_size = ROUNDUP(ta_head->stack_size,
					 TEE_TA_STACK_ALIGNMENT);

	state->ctx->mm_stack = tee_mm_alloc(&tee_mm_sec_ddr,
					    state->ctx->stack_size);
	if (!state->ctx->mm_stack) {
		EMSG("Failed to allocate %zu bytes for user stack",
		     state->ctx->stack_size);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Map physical memory into TA virtual memory
	 */

	res = tee_mmu_init(state->ctx);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_mmu_map(state->ctx, &param);
	if (res != TEE_SUCCESS)
		goto out;

	tee_mmu_set_ctx(state->ctx);

	dst = (void *)tee_mmu_get_load_addr(state->ctx);
	/*
	 * Zero initialize everything to make sure that all memory not
	 * updated from the ELF is zero (covering .bss and eventual gaps).
	 */
	memset(dst, 0, dst_size);

	/*
	 * Copy the segments
	 */
	memcpy(dst, ta_head, sizeof(struct ta_head));
	res = copy_to(state, dst, dst_size,
		      phdr[0].p_vaddr + sizeof(struct ta_head),
		      phdr[0].p_offset + sizeof(struct ta_head),
		      phdr[0].p_filesz - sizeof(struct ta_head));
	if (res != TEE_SUCCESS)
		goto out;

	for (n = 1; n < ehdr->e_phnum; n++) {
		if (phdr[n].p_type != PT_LOAD)
			continue;

		res = copy_to(state, dst, dst_size, phdr[n].p_vaddr,
			      phdr[n].p_offset, phdr[n].p_filesz);
		if (res != TEE_SUCCESS)
			goto out;
	}

	/*
	 * We have now loaded all segments into TA memory, now we need to
	 * process relocation information. To find relocation information
	 * we need to locate the section headers. The section headers are
	 * located somewhere between the last segment and the end of the
	 * ELF.
	 */
	if (ehdr->e_shoff < phdr[1].p_filesz) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	res = alloc_and_copy_to(&p, state, ehdr->e_shoff,
				ehdr->e_shnum * sizeof(Elf32_Shdr));
	if (res != TEE_SUCCESS)
		goto out;
	shdr = p;

	/* Hash until end of ELF */
	res = advance_to(state, state->nwdata_len);
	if (res != TEE_SUCCESS)
		goto out;

	/* Process relocation */
	for (n = 0; n < ehdr->e_shnum; n++) {
		if (shdr[n].sh_type == SHT_RELA) {
			res = TEE_ERROR_NOT_IMPLEMENTED;
			goto out;
		} else if (shdr[n].sh_type == SHT_REL) {
			res = el_process_rel(state, shdr, n, (vaddr_t)dst);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	cache_maintenance_l1(DCACHE_AREA_CLEAN, dst, dst_size);
	cache_maintenance_l1(ICACHE_AREA_INVALIDATE, dst, dst_size);
out:
	free(ehdr);
	free(phdr);
	free(ta_head);
	free(shdr);
	return res;

}
