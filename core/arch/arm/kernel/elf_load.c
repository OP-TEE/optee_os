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
#include "elf_common.h"
#include "elf_load.h"
#include "elf_load_dyn.h"
#include "elf_load_private.h"
#include "elf32.h"
#include "elf64.h"

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
			 bool is_main,
			 struct user_ta_elf_head *elfs,
			 TEE_Result (*resolve_sym)(
				struct user_ta_elf_head *elfs,
				const char *name, uintptr_t *val),
			 struct elf_load_state **ret_state)
{
	struct elf_load_state *state;
	TEE_Result res;

	state = calloc(1, sizeof(*state));
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->is_main = is_main;
	state->elfs = elfs;
	state->resolve_sym = resolve_sym;
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

static TEE_Result e32_load_ehdr(struct elf_load_state *state, Elf32_Ehdr *ehdr,
				vaddr_t *entry)
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
	if (entry)
		*entry = ehdr->e_entry;
	return TEE_SUCCESS;
}

#ifdef ARM64
static TEE_Result e64_load_ehdr(struct elf_load_state *state, Elf32_Ehdr *eh32,
				vaddr_t *entry)
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
	if (entry)
		*entry = ehdr->e_entry;
	return TEE_SUCCESS;
}
#else /*ARM64*/
static TEE_Result e64_load_ehdr(struct elf_load_state *state __unused,
			Elf32_Ehdr *eh32 __unused, vaddr_t *entry __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*ARM64*/

static TEE_Result get_max_va(struct elf_load_state *state, size_t *ret_vasize)
{
	struct elf_ehdr ehdr;
	struct elf_phdr phdr;
	size_t vasize = 0;
	size_t tmpsize;
	size_t n;

	copy_ehdr(&ehdr, state);

	for (n = 0; n < ehdr.e_phnum; n++) {
		copy_phdr(&phdr, state, n);
		if (phdr.p_type == PT_LOAD) {
			if (ADD_OVERFLOW(phdr.p_vaddr, phdr.p_memsz, &tmpsize))
				return TEE_ERROR_SECURITY;
			if (tmpsize > vasize)
				vasize = tmpsize;
		}
	}
	*ret_vasize = vasize;

	return TEE_SUCCESS;
}

static TEE_Result load_head(struct elf_load_state *state, size_t head_size)
{
	TEE_Result res;
	size_t n;
	void *p;
	struct elf_ehdr ehdr;
	struct elf_phdr ptload0;
	size_t phsize;

	copy_ehdr(&ehdr, state);
	/*
	 * Program headers:
	 * We're expecting at least one header of PT_LOAD type.
	 * For the main executable, the .ta_head section must be located first
	 * in the first PT_LOAD segment, which must start at virtual address 0.
	 * Dynamic libraries have no .ta_head.
	 * Other types of headers may appear before the first PT_LOAD (for
	 * example, GNU ld will typically insert a PT_ARM_EXIDX segment first
	 * when it encounters a .ARM.exidx section i.e., unwind tables for
	 * 32-bit binaries).
	 * The PT_DYNAMIC segment is ignored unless support for dynamically
	 * linked TAs is enabled.
	 * All sections not included by a PT_LOAD (or PT_DYNAMIC) segment are
	 * ignored.
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

	/* Calculate amount of required virtual memory for the ELF file */
	res = get_max_va(state, &state->vasize);
	if (res)
		return res;

	if (!state->is_main) {
		state->ta_head = NULL;
		state->ta_head_size = 0;
		return TEE_SUCCESS;
	}

	/* Read .ta_head from first segment if the segment is large enough */
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
			void **head, size_t *vasize, bool *is_32bit,
			vaddr_t *entry)
{
	TEE_Result res;
	Elf32_Ehdr ehdr;

	/*
	 * The ELF potentially resides in shared memory, to avoid attacks based
	 * on modifying the ELF while we're parsing it here we only read each
	 * byte from the ELF once. We're also hashing the ELF while reading
	 * so we're limited to only read the ELF sequentially from start to
	 * end.
	 */

	res = copy_to(state, &ehdr, sizeof(ehdr), 0, 0, sizeof(Elf32_Ehdr));
	if (res != TEE_SUCCESS)
		return res;

	if (!IS_ELF(ehdr))
		return TEE_ERROR_BAD_FORMAT;
	res = e32_load_ehdr(state, &ehdr, entry);
	if (res == TEE_ERROR_BAD_FORMAT)
		res = e64_load_ehdr(state, &ehdr, entry);
	if (res != TEE_SUCCESS)
		return res;

	res = load_head(state, head_size);
	if (res == TEE_SUCCESS) {
		*vasize = state->vasize;
		if (head_size) {
			*head = state->ta_head;
			*is_32bit = state->is_32bit;
		}
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
	size_t sh_end = 0;

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
		if (ADD_OVERFLOW(shdr[sym_tab_idx].sh_addr,
				 shdr[sym_tab_idx].sh_size, &sh_end))
			return TEE_ERROR_BAD_FORMAT;
		if (sh_end >= state->vasize)
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
	if (ADD_OVERFLOW(shdr[rel_sidx].sh_addr, shdr[rel_sidx].sh_size,
			 &sh_end))
		return TEE_ERROR_BAD_FORMAT;
	if (sh_end >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	rel_end = rel + shdr[rel_sidx].sh_size / sizeof(Elf32_Rel);
	for (; rel < rel_end; rel++) {
		Elf32_Addr *where;
		size_t sym_idx;
		TEE_Result res;

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
			if (sym_tab[sym_idx].st_shndx == SHN_UNDEF) {
				/* Symbol is external */
				res = e32_process_dyn_rel(state, rel, where);
				if (res)
					return res;
			} else {
				*where += vabase + sym_tab[sym_idx].st_value;
			}
			break;
		case R_ARM_REL32:
			sym_idx = ELF32_R_SYM(rel->r_info);
			if (sym_idx >= num_syms)
				return TEE_ERROR_BAD_FORMAT;
			*where += sym_tab[sym_idx].st_value - rel->r_offset;
			break;
		case R_ARM_RELATIVE:
			*where += vabase;
			break;
		case R_ARM_GLOB_DAT:
		case R_ARM_JUMP_SLOT:
			res = e32_process_dyn_rel(state, rel, where);
			if (res)
				return res;
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
	size_t sh_end = 0;

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
		if (ADD_OVERFLOW(shdr[sym_tab_idx].sh_addr,
				 shdr[sym_tab_idx].sh_size, &sh_end))
			return TEE_ERROR_BAD_FORMAT;
		if (sh_end >= state->vasize)
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
	if (ADD_OVERFLOW(shdr[rel_sidx].sh_addr, shdr[rel_sidx].sh_size,
			 &sh_end))
		return TEE_ERROR_BAD_FORMAT;
	if (sh_end >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	rela_end = rela + shdr[rel_sidx].sh_size / sizeof(Elf64_Rela);
	for (; rela < rela_end; rela++) {
		Elf64_Addr *where;
		size_t sym_idx;
		TEE_Result res;

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
			if (sym_tab[sym_idx].st_shndx == SHN_UNDEF) {
				/* Symbol is external */
				res = e64_process_dyn_rela(state, rela, where);
				if (res)
					return res;
			} else {
				*where = rela->r_addend +
					sym_tab[sym_idx].st_value + vabase;
			}
			break;
		case R_AARCH64_RELATIVE:
			*where = rela->r_addend + vabase;
			break;
		case R_AARCH64_GLOB_DAT:
		case R_AARCH64_JUMP_SLOT:
			res = e64_process_dyn_rela(state, rela, where);
			if (res)
				return res;
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
	size_t offs = 0;
	size_t e_p_hdr_sz;

	copy_ehdr(&ehdr, state);
	e_p_hdr_sz = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;

	/*
	 * Copy the segments
	 */
	if (state->ta_head_size) {
		memcpy(dst, state->ta_head, state->ta_head_size);
		offs = state->ta_head_size;
	}
	for (n = 0; n < ehdr.e_phnum; n++) {
		struct elf_phdr phdr;

		copy_phdr(&phdr, state, n);
		/*
		 * The PT_DYNAMIC segment is always included in a PT_LOAD
		 * segment so it can be ignored here.
		 */
		if (phdr.p_type != PT_LOAD)
			continue;

		if (phdr.p_offset < e_p_hdr_sz) {
			/*
			 * The first loadable segment contains the ELF and
			 * program headers, which have been read already.
			 * Make sure we don't try to read them again, thus
			 * going backwards in the data stream which is not
			 * supported by the TA store interface.
			 * We do not even need to copy the data from those
			 * headers because they are useless at this point.
			 * We can ignore them and leave zeroes at the beginning
			 * of the segment.
			 */
			offs += e_p_hdr_sz;
			e_p_hdr_sz = 0;
		}
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
		size_t sz = 0;

		if (MUL_OVERFLOW(ehdr.e_shnum, ehdr.e_shentsize, &sz))
			return TEE_ERROR_OUT_OF_MEMORY;
		res = alloc_and_copy_to(&p, state, ehdr.e_shoff, sz);
		if (res != TEE_SUCCESS)
			return res;
		state->shdr = p;
	}

	/* Hash until end of ELF */
	res = advance_to(state, state->data_len);
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

TEE_Result elf_process_rel(struct elf_load_state *state, vaddr_t vabase)
{
	TEE_Result (*process_rel)(struct elf_load_state *state,
				  size_t rel_sidx, vaddr_t vabase);
	struct elf_ehdr ehdr;
	TEE_Result res;
	size_t n;

	copy_ehdr(&ehdr, state);

	if (state->is_32bit)
		process_rel = e32_process_rel;
	else
		process_rel = e64_process_rel;

	for (n = 0; n < ehdr.e_shnum; n++) {
		uint32_t sh_type = get_shdr_type(state, n);

		if (sh_type == SHT_REL || sh_type == SHT_RELA) {
			res = process_rel(state, n, vabase);
			if (res != TEE_SUCCESS)
				return res;
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
