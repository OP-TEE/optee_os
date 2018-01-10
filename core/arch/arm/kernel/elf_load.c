// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <types_ext.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <kernel/tee_misc.h>
#include <kernel/user_ta.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <trace.h>
#include "elf_load.h"
#include "elf_common.h"
#include "elf32.h"
#include "elf64.h"

struct elf_load_state {
	bool is_32bit;

	struct user_ta_store_handle *ta_handle;
	const struct user_ta_store_ops *ta_store;
	size_t data_len;

	size_t next_offs;

	void *ta_head;
	size_t ta_head_size;

	void *ehdr;
	void *phdr;

	size_t vasize;
	void *shdr;
};

/* Replicates the fields we need from Elf{32,64}_Ehdr */
struct elf_ehdr {
	size_t e_phoff;
	size_t e_shoff;
	uint32_t e_phentsize;
	uint32_t e_phnum;
	uint32_t e_shentsize;
	uint32_t e_shnum;
};

/* Replicates the fields we need from Elf{32,64}_Phdr */
struct elf_phdr {
	uint32_t p_type;
	uint32_t p_flags;
	uintptr_t p_vaddr;
	size_t p_filesz;
	size_t p_memsz;
	size_t p_offset;
};

#ifdef ARM64
#define DO_ACTION(state, is_32bit_action, is_64bit_action) \
	do { \
		if ((state)->is_32bit) { \
			is_32bit_action; \
		} else { \
			is_64bit_action; \
		} \
	} while (0)
#else
/* No need to assert state->is_32bit since that is caught before this is used */
#define DO_ACTION(state, is_32bit_action, is_64bit_action) is_32bit_action
#endif

#define COPY_EHDR(dst, src) \
	do { \
		(dst)->e_phoff = (src)->e_phoff; \
		(dst)->e_shoff = (src)->e_shoff; \
		(dst)->e_phentsize = (src)->e_phentsize; \
		(dst)->e_phnum = (src)->e_phnum; \
		(dst)->e_shentsize = (src)->e_shentsize; \
		(dst)->e_shnum = (src)->e_shnum; \
	} while (0)
static void copy_ehdr(struct elf_ehdr *ehdr, struct elf_load_state *state)
{
	DO_ACTION(state, COPY_EHDR(ehdr, ((Elf32_Ehdr *)state->ehdr)),
			 COPY_EHDR(ehdr, ((Elf64_Ehdr *)state->ehdr)));
}

static uint32_t get_shdr_type(struct elf_load_state *state, size_t idx)
{
	DO_ACTION(state, return ((Elf32_Shdr *)state->shdr + idx)->sh_type,
			 return ((Elf64_Shdr *)state->shdr + idx)->sh_type);
}

#define COPY_PHDR(dst, src) \
	do { \
		(dst)->p_type = (src)->p_type; \
		(dst)->p_vaddr = (src)->p_vaddr; \
		(dst)->p_filesz = (src)->p_filesz; \
		(dst)->p_memsz = (src)->p_memsz; \
		(dst)->p_offset = (src)->p_offset; \
		(dst)->p_flags = (src)->p_flags; \
	} while (0)
static void copy_phdr(struct elf_phdr *phdr, struct elf_load_state *state,
			size_t idx)
{
	DO_ACTION(state, COPY_PHDR(phdr, ((Elf32_Phdr *)state->phdr + idx)),
			 COPY_PHDR(phdr, ((Elf64_Phdr *)state->phdr + idx)));
}

static TEE_Result advance_to(struct elf_load_state *state, size_t offs)
{
	TEE_Result res;

	if (offs < state->next_offs)
		return TEE_ERROR_BAD_STATE;
	if (offs == state->next_offs)
		return TEE_SUCCESS;

	if (offs > state->data_len)
		return TEE_ERROR_SECURITY;

	res = state->ta_store->read(state->ta_handle, NULL,
				    offs - state->next_offs);
	if (res != TEE_SUCCESS)
		return res;
	state->next_offs = offs;
	return TEE_SUCCESS;
}

static TEE_Result copy_to(struct elf_load_state *state,
			void *dst, size_t dst_size, size_t dst_offs,
			size_t offs, size_t len)
{
	TEE_Result res;
	size_t read_max;
	size_t data_max;

	res = advance_to(state, offs);
	if (res != TEE_SUCCESS)
		return res;
	if (!len)
		return TEE_SUCCESS;

	if (ADD_OVERFLOW(len, dst_offs, &read_max) || read_max > dst_size ||
	    ADD_OVERFLOW(len, offs, &data_max) || data_max > state->data_len)
		return TEE_ERROR_SECURITY;

	res = state->ta_store->read(state->ta_handle,
				    (uint8_t *)dst + dst_offs,
				    len);
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

TEE_Result elf_load_init(const struct user_ta_store_ops *ta_store,
			 struct user_ta_store_handle *ta_handle,
			 struct elf_load_state **ret_state)
{
	struct elf_load_state *state;
	TEE_Result res;

	state = calloc(1, sizeof(*state));
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->ta_store = ta_store;
	state->ta_handle = ta_handle;
	res = ta_store->get_size(ta_handle, &state->data_len);
	if (res != TEE_SUCCESS) {
		free(state);
		return res;
	}

	*ret_state = state;
	return res;
}

static TEE_Result e32_load_ehdr(struct elf_load_state *state, Elf32_Ehdr *ehdr)
{
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE ||
	    ehdr->e_type != ET_DYN || ehdr->e_machine != EM_ARM ||
	    (ehdr->e_flags & EF_ARM_ABIMASK) != EF_ARM_ABI_VERSION ||
#ifndef CFG_WITH_VFP
	    (ehdr->e_flags & EF_ARM_ABI_FLOAT_HARD) ||
#endif
	    ehdr->e_phentsize != sizeof(Elf32_Phdr) ||
	    ehdr->e_shentsize != sizeof(Elf32_Shdr))
		return TEE_ERROR_BAD_FORMAT;

	state->ehdr = malloc(sizeof(*ehdr));
	if (!state->ehdr)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(state->ehdr, ehdr, sizeof(*ehdr));
	state->is_32bit = true;
	return TEE_SUCCESS;
}

#ifdef ARM64
static TEE_Result e64_load_ehdr(struct elf_load_state *state, Elf32_Ehdr *eh32)
{
	TEE_Result res;
	Elf64_Ehdr *ehdr = NULL;

	if (eh32->e_ident[EI_VERSION] != EV_CURRENT ||
	    eh32->e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh32->e_ident[EI_DATA] != ELFDATA2LSB ||
	    eh32->e_ident[EI_OSABI] != ELFOSABI_NONE ||
	    eh32->e_type != ET_DYN || eh32->e_machine != EM_AARCH64)
		return TEE_ERROR_BAD_FORMAT;

	ehdr = malloc(sizeof(*ehdr));
	if (!ehdr)
		return TEE_ERROR_OUT_OF_MEMORY;
	state->ehdr = ehdr;
	memcpy(ehdr, eh32, sizeof(*eh32));
	res = copy_to(state, ehdr, sizeof(*ehdr), sizeof(*eh32),
		      sizeof(*eh32), sizeof(*ehdr) - sizeof(*eh32));
	if (res != TEE_SUCCESS)
		return res;

	if (ehdr->e_flags || ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
	    ehdr->e_shentsize != sizeof(Elf64_Shdr))
		return TEE_ERROR_BAD_FORMAT;

	state->ehdr = ehdr;
	state->is_32bit = false;
	return TEE_SUCCESS;
}
#else /*ARM64*/
static TEE_Result e64_load_ehdr(struct elf_load_state *state __unused,
			Elf32_Ehdr *eh32 __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*ARM64*/

static TEE_Result load_head(struct elf_load_state *state, size_t head_size)
{
	TEE_Result res;
	size_t n;
	void *p;
	struct elf_ehdr ehdr;
	struct elf_phdr phdr;
	struct elf_phdr ptload0;
	size_t phsize;

	copy_ehdr(&ehdr, state);
	/*
	 * Program headers:
	 * We're expecting at least one header of PT_LOAD type.
	 * .ta_head must be located first in the first PT_LOAD header, which
	 * must start at virtual address 0. Other types of headers may appear
	 * before the first PT_LOAD (for example, GNU ld will typically insert
	 * a PT_ARM_EXIDX segment first when it encounters a .ARM.exidx section
	 * i.e., unwind tables for 32-bit binaries).
	 * The last PT_LOAD header gives the maximum VA.
	 * A PT_DYNAMIC segment may appear, but is ignored.
	 * All sections not included by a PT_LOAD segment are ignored.
	 */
	if (ehdr.e_phnum < 1)
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW(ehdr.e_phnum, ehdr.e_phentsize, &phsize))
		return TEE_ERROR_SECURITY;

	res = alloc_and_copy_to(&p, state, ehdr.e_phoff, phsize);
	if (res != TEE_SUCCESS)
		return res;
	state->phdr = p;

	/*
	 * Check that the first program header of type PT_LOAD starts at
	 * virtual address 0.
	 */
	for (n = 0; n < ehdr.e_phnum; n++) {
		copy_phdr(&ptload0, state, n);
		if (ptload0.p_type == PT_LOAD)
			break;
	}
	if (ptload0.p_type != PT_LOAD || ptload0.p_vaddr != 0)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Calculate amount of required virtual memory for TA. Find the max
	 * address used by a PT_LOAD type. Note that last PT_LOAD type
	 * dictates the total amount of needed memory. Eventual holes in
	 * the memory will also be allocated.
	 *
	 * Note that this loop will terminate at n = 0 if not earlier
	 * as we already know from above that we have at least one PT_LOAD
	 */
	n = ehdr.e_phnum;
	do {
		n--;
		copy_phdr(&phdr, state, n);
	} while (phdr.p_type != PT_LOAD);

	if (ADD_OVERFLOW(phdr.p_vaddr, phdr.p_memsz, &state->vasize))
		return TEE_ERROR_SECURITY;

	/*
	 * Read .ta_head from first segment, make sure the segment is large
	 * enough. We're only interested in seeing that the
	 * TA_FLAG_EXEC_DDR flag is set. If that's true we set that flag in
	 * the TA context to enable mapping the TA. Later when this
	 * function has returned and the hash has been verified the flags
	 * field will be updated with eventual other flags.
	 */
	if (ptload0.p_filesz < head_size)
		return TEE_ERROR_BAD_FORMAT;
	res = alloc_and_copy_to(&p, state, ptload0.p_offset, head_size);
	if (res == TEE_SUCCESS) {
		state->ta_head = p;
		state->ta_head_size = head_size;
	}
	return res;
}

TEE_Result elf_load_head(struct elf_load_state *state, size_t head_size,
			void **head, size_t *vasize, bool *is_32bit)
{
	TEE_Result res;
	Elf32_Ehdr ehdr;

	/*
	 * The ELF resides in shared memory, to avoid attacks based on
	 * modifying the ELF while we're parsing it here we only read each
	 * byte from the ELF once. We're also hashing the ELF while reading
	 * so we're limited to only read the ELF sequentially from start to
	 * end.
	 */

	res = copy_to(state, &ehdr, sizeof(ehdr), 0, 0, sizeof(Elf32_Ehdr));
	if (res != TEE_SUCCESS)
		return res;

	if (!IS_ELF(ehdr))
		return TEE_ERROR_BAD_FORMAT;
	res = e32_load_ehdr(state, &ehdr);
	if (res == TEE_ERROR_BAD_FORMAT)
		res = e64_load_ehdr(state, &ehdr);
	if (res != TEE_SUCCESS)
		return res;

	res = load_head(state, head_size);
	if (res == TEE_SUCCESS) {
		*head = state->ta_head;
		*vasize = state->vasize;
		*is_32bit = state->is_32bit;
	}
	return res;
}

TEE_Result elf_load_get_next_segment(struct elf_load_state *state, size_t *idx,
			vaddr_t *vaddr, size_t *size, uint32_t *flags,
			uint32_t *type)
{
	struct elf_ehdr ehdr;

	copy_ehdr(&ehdr, state);
	if (*idx < ehdr.e_phnum) {
		struct elf_phdr phdr;

		copy_phdr(&phdr, state, *idx);
		(*idx)++;
		if (vaddr)
			*vaddr = phdr.p_vaddr;
		if (size)
			*size = phdr.p_memsz;
		if (flags)
			*flags = phdr.p_flags;
		if (type)
			*type = phdr.p_type;
		return TEE_SUCCESS;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result e32_process_rel(struct elf_load_state *state, size_t rel_sidx,
			vaddr_t vabase)
{
	Elf32_Ehdr *ehdr = state->ehdr;
	Elf32_Shdr *shdr = state->shdr;
	Elf32_Rel *rel;
	Elf32_Rel *rel_end;
	size_t sym_tab_idx;
	Elf32_Sym *sym_tab = NULL;
	size_t num_syms = 0;

	if (shdr[rel_sidx].sh_type != SHT_REL)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (shdr[rel_sidx].sh_entsize != sizeof(Elf32_Rel))
		return TEE_ERROR_BAD_FORMAT;

	sym_tab_idx = shdr[rel_sidx].sh_link;
	if (sym_tab_idx) {
		if (sym_tab_idx >= ehdr->e_shnum)
			return TEE_ERROR_BAD_FORMAT;

		if (shdr[sym_tab_idx].sh_entsize != sizeof(Elf32_Sym))
			return TEE_ERROR_BAD_FORMAT;

		/* Check the address is inside TA memory */
		if (shdr[sym_tab_idx].sh_addr > state->vasize ||
		    (shdr[sym_tab_idx].sh_addr +
				shdr[sym_tab_idx].sh_size) > state->vasize)
			return TEE_ERROR_BAD_FORMAT;

		sym_tab = (Elf32_Sym *)(vabase + shdr[sym_tab_idx].sh_addr);
		if (!ALIGNMENT_IS_OK(sym_tab, Elf32_Sym))
			return TEE_ERROR_BAD_FORMAT;

		num_syms = shdr[sym_tab_idx].sh_size / sizeof(Elf32_Sym);
	}

	/* Check the address is inside TA memory */
	if (shdr[rel_sidx].sh_addr >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	rel = (Elf32_Rel *)(vabase + shdr[rel_sidx].sh_addr);
	if (!ALIGNMENT_IS_OK(rel, Elf32_Rel))
		return TEE_ERROR_BAD_FORMAT;

	/* Check the address is inside TA memory */
	if ((shdr[rel_sidx].sh_addr + shdr[rel_sidx].sh_size) >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	rel_end = rel + shdr[rel_sidx].sh_size / sizeof(Elf32_Rel);
	for (; rel < rel_end; rel++) {
		Elf32_Addr *where;
		size_t sym_idx;

		/* Check the address is inside TA memory */
		if (rel->r_offset >= state->vasize)
			return TEE_ERROR_BAD_FORMAT;

		where = (Elf32_Addr *)(vabase + rel->r_offset);
		if (!ALIGNMENT_IS_OK(where, Elf32_Addr))
			return TEE_ERROR_BAD_FORMAT;

		switch (ELF32_R_TYPE(rel->r_info)) {
		case R_ARM_ABS32:
			sym_idx = ELF32_R_SYM(rel->r_info);
			if (sym_idx >= num_syms)
				return TEE_ERROR_BAD_FORMAT;

			*where += vabase + sym_tab[sym_idx].st_value;
			break;
		case R_ARM_RELATIVE:
			*where += vabase;
			break;
		default:
			EMSG("Unknown relocation type %d",
			     ELF32_R_TYPE(rel->r_info));
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	return TEE_SUCCESS;
}

#ifdef ARM64
static TEE_Result e64_process_rel(struct elf_load_state *state,
			size_t rel_sidx, vaddr_t vabase)
{
	Elf64_Ehdr *ehdr = state->ehdr;
	Elf64_Shdr *shdr = state->shdr;
	Elf64_Rela *rela;
	Elf64_Rela *rela_end;
	size_t sym_tab_idx;
	Elf64_Sym *sym_tab = NULL;
	size_t num_syms = 0;

	if (shdr[rel_sidx].sh_type != SHT_RELA)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (shdr[rel_sidx].sh_entsize != sizeof(Elf64_Rela))
		return TEE_ERROR_BAD_FORMAT;

	sym_tab_idx = shdr[rel_sidx].sh_link;
	if (sym_tab_idx) {
		if (sym_tab_idx >= ehdr->e_shnum)
			return TEE_ERROR_BAD_FORMAT;

		if (shdr[sym_tab_idx].sh_entsize != sizeof(Elf64_Sym))
			return TEE_ERROR_BAD_FORMAT;

		/* Check the address is inside TA memory */
		if (shdr[sym_tab_idx].sh_addr > state->vasize ||
		    (shdr[sym_tab_idx].sh_addr +
				shdr[sym_tab_idx].sh_size) > state->vasize)
			return TEE_ERROR_BAD_FORMAT;

		sym_tab = (Elf64_Sym *)(vabase + shdr[sym_tab_idx].sh_addr);
		if (!ALIGNMENT_IS_OK(sym_tab, Elf64_Sym))
			return TEE_ERROR_BAD_FORMAT;

		num_syms = shdr[sym_tab_idx].sh_size / sizeof(Elf64_Sym);
	}

	/* Check the address is inside TA memory */
	if (shdr[rel_sidx].sh_addr >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	rela = (Elf64_Rela *)(vabase + shdr[rel_sidx].sh_addr);
	if (!ALIGNMENT_IS_OK(rela, Elf64_Rela))
		return TEE_ERROR_BAD_FORMAT;

	/* Check the address is inside TA memory */
	if ((shdr[rel_sidx].sh_addr + shdr[rel_sidx].sh_size) >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	rela_end = rela + shdr[rel_sidx].sh_size / sizeof(Elf64_Rela);
	for (; rela < rela_end; rela++) {
		Elf64_Addr *where;
		size_t sym_idx;

		/* Check the address is inside TA memory */
		if (rela->r_offset >= state->vasize)
			return TEE_ERROR_BAD_FORMAT;

		where = (Elf64_Addr *)(vabase + rela->r_offset);
		if (!ALIGNMENT_IS_OK(where, Elf64_Addr))
			return TEE_ERROR_BAD_FORMAT;

		switch (ELF64_R_TYPE(rela->r_info)) {
		case R_AARCH64_ABS64:
			sym_idx = ELF64_R_SYM(rela->r_info);
			if (sym_idx > num_syms)
				return TEE_ERROR_BAD_FORMAT;
			*where = rela->r_addend + sym_tab[sym_idx].st_value +
				 vabase;
			break;
		case R_AARCH64_RELATIVE:
			*where = rela->r_addend + vabase;
			break;
		default:
			EMSG("Unknown relocation type %zd",
			     ELF64_R_TYPE(rela->r_info));
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	return TEE_SUCCESS;
}
#else /*ARM64*/
static TEE_Result e64_process_rel(struct elf_load_state *state __unused,
			size_t rel_sidx __unused, vaddr_t vabase __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*ARM64*/

TEE_Result elf_load_body(struct elf_load_state *state, vaddr_t vabase)
{
	TEE_Result res;
	size_t n;
	void *p;
	uint8_t *dst = (uint8_t *)vabase;
	struct elf_ehdr ehdr;
	size_t offs;

	copy_ehdr(&ehdr, state);

	/*
	 * Zero initialize everything to make sure that all memory not
	 * updated from the ELF is zero (covering .bss and eventual gaps).
	 */
	memset(dst, 0, state->vasize);

	/*
	 * Copy the segments
	 */
	memcpy(dst, state->ta_head, state->ta_head_size);
	offs = state->ta_head_size;
	for (n = 0; n < ehdr.e_phnum; n++) {
		struct elf_phdr phdr;

		copy_phdr(&phdr, state, n);
		if (phdr.p_type != PT_LOAD)
			continue;

		res = copy_to(state, dst, state->vasize,
			      phdr.p_vaddr + offs,
			      phdr.p_offset + offs,
			      phdr.p_filesz - offs);
		if (res != TEE_SUCCESS)
			return res;
		offs = 0;
	}

	/*
	 * We have now loaded all segments into TA memory, now we need to
	 * process relocation information. To find relocation information
	 * we need to locate the section headers. The section headers are
	 * located somewhere between the last segment and the end of the
	 * ELF.
	 */
	if (ehdr.e_shoff) {
		/* We have section headers */
		res = alloc_and_copy_to(&p, state, ehdr.e_shoff,
					ehdr.e_shnum * ehdr.e_shentsize);
		if (res != TEE_SUCCESS)
			return res;
		state->shdr = p;
	}

	/* Hash until end of ELF */
	res = advance_to(state, state->data_len);
	if (res != TEE_SUCCESS)
		return res;

	if (state->shdr) {
		TEE_Result (*process_rel)(struct elf_load_state *state,
					size_t rel_sidx, vaddr_t vabase);

		if (state->is_32bit)
			process_rel = e32_process_rel;
		else
			process_rel = e64_process_rel;

		/* Process relocation */
		for (n = 0; n < ehdr.e_shnum; n++) {
			uint32_t sh_type = get_shdr_type(state, n);

			if (sh_type == SHT_REL || sh_type == SHT_RELA) {
				res = process_rel(state, n, vabase);
				if (res != TEE_SUCCESS)
					return res;
			}
		}
	}

	return TEE_SUCCESS;
}

void elf_load_final(struct elf_load_state *state)
{
	if (state) {
		free(state->ta_head);
		free(state->ehdr);
		free(state->phdr);
		free(state->shdr);
		free(state);
	}
}
