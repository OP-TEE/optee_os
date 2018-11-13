// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdlib.h>
#include <string.h>
#include <types_ext.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <util.h>
#include "elf_common.h"
#include "elf_load_dyn.h"
#include "elf_load_private.h"

TEE_Result elf_resolve_symbol(struct elf_load_state *state,
			      const char *name, uintptr_t *val)
{
	struct elf_sym sym;
	size_t n;

	for (n = 0; copy_sym(&sym, n, state); n++) {
		if (sym.st_shndx == SHN_UNDEF)
			continue;
		if (!strcmp(name, &state->dynstr[sym.st_name])) {
			*val = sym.st_value;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static size_t e32_name_idx_nospec(Elf32_Sym *sym_tab, size_t num_syms,
				  size_t sym_idx)
{
	Elf32_Sym *s_upper = sym_tab + num_syms;
	Elf32_Sym *s_item = sym_tab + sym_idx;
	Elf32_Word *lower = &sym_tab->st_name;
	Elf32_Word *upper = &s_upper->st_name;
	Elf32_Word *item = &s_item->st_name;

	return load_no_speculate_fail(item, lower, upper, SIZE_MAX);
}

static char *name_nospec(char *dyn_str, size_t dynstr_size, size_t name_idx)
{
	char *lower = dyn_str;
	char *upper = dyn_str + dynstr_size;
	char *name = dyn_str + name_idx;

	return load_no_speculate_cmp(&name, lower, upper, NULL, name);
}

TEE_Result e32_process_dyn_rel(struct elf_load_state *state, Elf32_Rel *rel,
			       Elf32_Addr *where)
{
	size_t sym_idx;
	char *name;
	uint8_t bind;
	uintptr_t val;
	size_t name_idx;
	TEE_Result res;
	Elf32_Sym *sym_tab = (Elf32_Sym *)state->dynsym;

	sym_idx = ELF32_R_SYM(rel->r_info);
	name_idx = e32_name_idx_nospec(sym_tab,
				       state->dynsym_size / sizeof(Elf32_Sym),
				       sym_idx);
	if (name_idx == SIZE_MAX)
		return TEE_ERROR_BAD_FORMAT;
	name = name_nospec(state->dynstr, state->dynstr_size,
			name_idx);
	if (!name)
		return TEE_ERROR_BAD_FORMAT;
	bind = ELF32_ST_BIND(sym_tab[sym_idx].st_info);
	if (bind != STB_GLOBAL && bind != STB_WEAK)
		return TEE_ERROR_BAD_FORMAT;
	res = state->resolve_sym(state->elfs, name, &val);
	if (res)
		return res;
	*where = val;

	return TEE_SUCCESS;
}

#ifdef ARM64
static size_t e64_name_idx_nospec(Elf64_Sym *sym_tab, size_t num_syms,
				  size_t sym_idx)
{
	Elf64_Sym *s_upper = sym_tab + num_syms;
	Elf64_Sym *s_item = sym_tab + sym_idx;
	Elf64_Word *lower = &sym_tab->st_name;
	Elf64_Word *upper = &s_upper->st_name;
	Elf64_Word *item = &s_item->st_name;

	return load_no_speculate_fail(item, lower, upper, SIZE_MAX);
}

TEE_Result e64_process_dyn_rela(struct elf_load_state *state, Elf64_Rela *rel,
				Elf64_Addr *where)
{
	size_t sym_idx;
	char *name;
	uint8_t bind;
	uintptr_t val;
	size_t name_idx;
	TEE_Result res;
	Elf64_Sym *sym_tab = (Elf64_Sym *)state->dynsym;

	sym_idx = ELF64_R_SYM(rel->r_info);
	name_idx = e64_name_idx_nospec(sym_tab,
				       state->dynsym_size / sizeof(Elf64_Sym),
				       sym_idx);
	if (name_idx == SIZE_MAX)
		return TEE_ERROR_BAD_FORMAT;
	name = name_nospec(state->dynstr, state->dynstr_size,
			name_idx);
	if (!name)
		return TEE_ERROR_BAD_FORMAT;
	bind = ELF64_ST_BIND(sym_tab[sym_idx].st_info);
	if (bind != STB_GLOBAL && bind != STB_WEAK)
		return TEE_ERROR_BAD_FORMAT;
	res = state->resolve_sym(state->elfs, name, &val);
	if (res)
		return res;
	*where = val;

	return TEE_SUCCESS;
}
#endif

/* Check the dynamic segment and save info for later */
static TEE_Result read_dyn_segment(struct elf_load_state *state,
				   vaddr_t vabase)
{
	struct elf_ehdr ehdr;
	struct elf_shdr shdr = { 0, };
	struct elf_dyn dyn;
	vaddr_t dynstr = 0;
	size_t dynstr_size = 0;
	vaddr_t dynsym = 0;
	size_t dynsym_size;
	vaddr_t max;
	size_t n;

	/*
	 * Find the address and size of the string table (.strtab)
	 */
	for (n = 0; copy_dyn(&dyn, n, state); n++) {
		if (dyn.d_tag == DT_STRTAB)
			dynstr = dyn.d_un.d_ptr;
		else if (dyn.d_tag == DT_STRSZ)
			dynstr_size = dyn.d_un.d_val;
	}
	if (!dynstr || dynstr >= state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	if (!dynstr_size || ADD_OVERFLOW(dynstr, dynstr_size, &max) ||
			max > state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	state->dynstr = (char *)(vabase + dynstr);
	state->dynstr_size = dynstr_size;

	/*
	 * Find the .dynsym section (contains the global symbols).
	 * There is an entry for it (DT_SYMTAB) in the .dynamic section, so we
	 * could use the above loop to find the section address. Unfortunately,
	 * the size information is not present. So, we have to parse the
	 * section headers instead.
	 */

	copy_ehdr(&ehdr, state);
	for (n = 0; n < ehdr.e_shnum; n++) {
		copy_shdr(&shdr, n, state);
		if (shdr.sh_type == SHT_DYNSYM)
			break;
	}
	if (n == ehdr.e_shnum)
		return TEE_ERROR_BAD_FORMAT;
	dynsym = shdr.sh_addr;
	dynsym_size = shdr.sh_size;
	if (!dynsym || dynsym >= state->vasize ||
			ADD_OVERFLOW(dynsym, dynsym_size, &max) ||
			max > state->vasize)
		return TEE_ERROR_BAD_FORMAT;
	state->dynsym = (void *)(vabase + dynsym);
	state->dynsym_size = dynsym_size;

	return TEE_SUCCESS;
}

static TEE_Result get_needed(struct elf_load_state *state,
			     vaddr_t vabase, char ***names_ret,
			     size_t *num_names_ret)

{
	struct elf_dyn dyn;
	size_t offs;
	TEE_Result res;
	size_t num_names = 0;
	char **names = NULL;
	size_t n;

	res = read_dyn_segment(state, vabase);
	if (res)
		return res;

	/* Now look for needed libraries and fill output array */
	for (n = 0; copy_dyn(&dyn, n, state); n++) {
		void *p;

		if (dyn.d_tag != DT_NEEDED)
			continue;
		if (!state->dynstr) {
			free(names);
			return TEE_ERROR_BAD_FORMAT;
		}
		p = realloc(names, (num_names + 1) * sizeof(char *));
		if (!p) {
			free(names);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
		names = p;
		offs = dyn.d_un.d_val;
		names[num_names] = (char *)state->dynstr + offs;
		num_names++;
	}

	*names_ret = names;
	*num_names_ret = num_names;
	return TEE_SUCCESS;
}

/*
 * Returns the names of all the libraries needed by the ELF file described
 * by @state. @needed is allocated by the function. The strings point to the
 * ELF string tables in the TA memory.
 */
TEE_Result elf_get_needed(struct elf_load_state *state, vaddr_t vabase,
			  char ***needed, size_t *num_needed)
{
	struct elf_ehdr ehdr;
	size_t n;
	vaddr_t dyn_addr;
	size_t dyn_sz;

	/*
	 * Find the dynamic section from the program headers, then call the
	 * proper parsing function.
	 */
	copy_ehdr(&ehdr, state);
	for (n = 0; n < ehdr.e_phnum; n++) {
		struct elf_phdr phdr;

		copy_phdr(&phdr, state, n);
		if (phdr.p_type == PT_DYNAMIC) {
			dyn_addr = phdr.p_vaddr;
			dyn_sz = phdr.p_memsz;
			if (dyn_addr > state->vasize)
				return TEE_ERROR_BAD_FORMAT;
			if (dyn_addr + dyn_sz > state->vasize)
				return TEE_ERROR_BAD_FORMAT;
			state->dyn = (void *)(vabase + dyn_addr);
			state->dyn_size = dyn_sz;
			return get_needed(state, vabase, needed, num_needed);
		}
	}

	return TEE_SUCCESS;
}
