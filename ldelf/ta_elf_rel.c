// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <elf32.h>
#include <elf64.h>
#include <elf_common.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>

#include "sys.h"
#include "ta_elf.h"

static uint32_t elf_hash(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;
	uint32_t h = 0;
	uint32_t g = 0;

	while (*p) {
		h = (h << 4) + *p++;
		g = h & 0xf0000000;
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

static bool __resolve_sym(struct ta_elf *elf, unsigned int st_bind,
			  unsigned int st_type, size_t st_shndx,
			  size_t st_name, size_t st_value, const char *name,
			  vaddr_t *val)
{
	if (st_bind != STB_GLOBAL)
		return false;
	if (st_shndx == SHN_UNDEF || st_shndx == SHN_XINDEX)
		return false;
	if (!st_name)
		return false;
	if (st_name > elf->dynstr_size)
		err(TEE_ERROR_BAD_FORMAT, "Symbol name out of range");

	if (strcmp(name, elf->dynstr + st_name))
		return false;

	if (st_value > (elf->max_addr - elf->load_addr))
		err(TEE_ERROR_BAD_FORMAT, "Symbol location out of range");

	switch (st_type) {
	case STT_OBJECT:
	case STT_FUNC:
		*val = st_value + elf->load_addr;
		break;
	default:
		err(TEE_ERROR_NOT_SUPPORTED, "Symbol type not supported");
	}

	return true;
}

static TEE_Result resolve_sym_helper(uint32_t hash, const char *name,
				     vaddr_t *val, struct ta_elf *elf)
{
	/*
	 * Using uint32_t here for convenience because both Elf64_Word
	 * and Elf32_Word are 32-bit types
	 */
	uint32_t *hashtab = elf->hashtab;
	uint32_t nbuckets = hashtab[0];
	uint32_t nchains = hashtab[1];
	uint32_t *bucket = &hashtab[2];
	uint32_t *chain = &bucket[nbuckets];
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Sym *sym = elf->dynsymtab;

		for (n = bucket[hash % nbuckets]; n; n = chain[n]) {
			if (n >= nchains || n >= elf->num_dynsyms)
				err(TEE_ERROR_BAD_FORMAT,
				    "Index out of range");
			if (__resolve_sym(elf,
					  ELF32_ST_BIND(sym[n].st_info),
					  ELF32_ST_TYPE(sym[n].st_info),
					  sym[n].st_shndx,
					  sym[n].st_name,
					  sym[n].st_value, name, val))
				return TEE_SUCCESS;
		}
	} else {
		Elf64_Sym *sym = elf->dynsymtab;

		for (n = bucket[hash % nbuckets]; n; n = chain[n]) {
			if (n >= nchains || n >= elf->num_dynsyms)
				err(TEE_ERROR_BAD_FORMAT,
				    "Index out of range");
			if (__resolve_sym(elf,
					  ELF64_ST_BIND(sym[n].st_info),
					  ELF64_ST_TYPE(sym[n].st_info),
					  sym[n].st_shndx,
					  sym[n].st_name,
					  sym[n].st_value, name, val))
				return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result ta_elf_resolve_sym(const char *name, vaddr_t *val,
			      struct ta_elf *elf)
{
	uint32_t hash = elf_hash(name);

	if (elf)
		return resolve_sym_helper(hash, name, val, elf);

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		if (!resolve_sym_helper(hash, name, val, elf))
			return TEE_SUCCESS;

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static void resolve_sym(const char *name, vaddr_t *val)
{
	TEE_Result res = ta_elf_resolve_sym(name, val, NULL);

	if (res)
		err(res, "Symbol %s not found", name);
}

static void e32_process_dyn_rel(const Elf32_Sym *sym_tab, size_t num_syms,
				const char *str_tab, size_t str_tab_size,
				Elf32_Rel *rel, Elf32_Addr *where)
{
	size_t sym_idx = 0;
	const char *name = NULL;
	vaddr_t val = 0;
	size_t name_idx = 0;

	sym_idx = ELF32_R_SYM(rel->r_info);
	if (sym_idx >= num_syms)
		err(TEE_ERROR_GENERIC, "Symbol index out of range");

	name_idx = sym_tab[sym_idx].st_name;
	if (name_idx >= str_tab_size)
		err(TEE_ERROR_GENERIC, "Name index out of range");
	name = str_tab + name_idx;

	resolve_sym(name, &val);
	*where = val;
}

static void e32_relocate(struct ta_elf *elf, unsigned int rel_sidx)
{
	Elf32_Shdr *shdr = elf->shdr;
	Elf32_Rel *rel = NULL;
	Elf32_Rel *rel_end = NULL;
	size_t sym_tab_idx = 0;
	Elf32_Sym *sym_tab = NULL;
	size_t num_syms = 0;
	size_t sh_end = 0;
	const char *str_tab = NULL;
	size_t str_tab_size = 0;

	assert(shdr[rel_sidx].sh_type == SHT_REL);

	assert(shdr[rel_sidx].sh_entsize == sizeof(Elf32_Rel));

	sym_tab_idx = shdr[rel_sidx].sh_link;
	if (sym_tab_idx) {
		size_t str_tab_idx = 0;

		if (sym_tab_idx >= elf->e_shnum)
			err(TEE_ERROR_GENERIC, "Symtab index out of range");

		assert(shdr[sym_tab_idx].sh_entsize == sizeof(Elf32_Sym));

		/* Check the address is inside ELF memory */
		if (ADD_OVERFLOW(shdr[sym_tab_idx].sh_addr,
				 shdr[sym_tab_idx].sh_size, &sh_end))
			err(TEE_ERROR_SECURITY, "Overflow");
		if (sh_end >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_GENERIC, "Symbol table out of range");

		sym_tab = (Elf32_Sym *)(elf->load_addr +
					shdr[sym_tab_idx].sh_addr);

		num_syms = shdr[sym_tab_idx].sh_size / sizeof(Elf32_Sym);

		str_tab_idx = shdr[sym_tab_idx].sh_link;
		if (str_tab_idx) {
			/* Check the address is inside ELF memory */
			if (ADD_OVERFLOW(shdr[str_tab_idx].sh_addr,
					 shdr[str_tab_idx].sh_size, &sh_end))
				err(TEE_ERROR_SECURITY, "Overflow");
			if (sh_end >= (elf->max_addr - elf->load_addr))
				err(TEE_ERROR_GENERIC,
				    "String table out of range");

			str_tab = (const char *)(elf->load_addr +
						 shdr[str_tab_idx].sh_addr);
			str_tab_size = shdr[str_tab_idx].sh_size;
		}
	}

	/* Check the address is inside TA memory */
	if (ADD_OVERFLOW(shdr[rel_sidx].sh_addr,
			 shdr[rel_sidx].sh_size, &sh_end))
		err(TEE_ERROR_SECURITY, "Overflow");
	if (sh_end >= (elf->max_addr - elf->load_addr))
		err(TEE_ERROR_GENERIC, "Relocation table out of range");
	rel = (Elf32_Rel *)(elf->load_addr + shdr[rel_sidx].sh_addr);

	rel_end = rel + shdr[rel_sidx].sh_size / sizeof(Elf32_Rel);
	for (; rel < rel_end; rel++) {
		Elf32_Addr *where = NULL;
		size_t sym_idx = 0;

		/* Check the address is inside TA memory */
		if (rel->r_offset >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_GENERIC,
			    "Relocation offset out of range");
		where = (Elf32_Addr *)(elf->load_addr + rel->r_offset);

		switch (ELF32_R_TYPE(rel->r_info)) {
		case R_ARM_ABS32:
			sym_idx = ELF32_R_SYM(rel->r_info);
			if (sym_idx >= num_syms)
				err(TEE_ERROR_GENERIC,
				    "Symbol index out of range");
			if (sym_tab[sym_idx].st_shndx == SHN_UNDEF) {
				/* Symbol is external */
				e32_process_dyn_rel(sym_tab, num_syms, str_tab,
						    str_tab_size, rel, where);
			} else {
				*where += elf->load_addr +
					  sym_tab[sym_idx].st_value;
			}
			break;
		case R_ARM_REL32:
			sym_idx = ELF32_R_SYM(rel->r_info);
			if (sym_idx >= num_syms)
				err(TEE_ERROR_GENERIC,
				    "Symbol index out of range");
			*where += sym_tab[sym_idx].st_value - rel->r_offset;
			break;
		case R_ARM_RELATIVE:
			*where += elf->load_addr;
			break;
		case R_ARM_GLOB_DAT:
		case R_ARM_JUMP_SLOT:
			e32_process_dyn_rel(sym_tab, num_syms, str_tab,
					    str_tab_size, rel, where);
			break;
		default:
			err(TEE_ERROR_BAD_FORMAT, "Unknown relocation type %d",
			     ELF32_R_TYPE(rel->r_info));
		}
	}
}

#ifdef ARM64
static void e64_process_dyn_rela(const Elf64_Sym *sym_tab, size_t num_syms,
				 const char *str_tab, size_t str_tab_size,
				 Elf64_Rela *rela, Elf64_Addr *where)
{
	size_t sym_idx = 0;
	const char *name = NULL;
	uintptr_t val = 0;
	size_t name_idx = 0;

	sym_idx = ELF64_R_SYM(rela->r_info);
	if (sym_idx >= num_syms)
		err(TEE_ERROR_GENERIC, "Symbol index out of range");

	name_idx = sym_tab[sym_idx].st_name;
	if (name_idx >= str_tab_size)
		err(TEE_ERROR_GENERIC, "Name index out of range");
	name = str_tab + name_idx;

	resolve_sym(name, &val);
	*where = val;
}

static void e64_relocate(struct ta_elf *elf, unsigned int rel_sidx)
{
	Elf64_Shdr *shdr = elf->shdr;
	Elf64_Rela *rela = NULL;
	Elf64_Rela *rela_end = NULL;
	size_t sym_tab_idx = 0;
	Elf64_Sym *sym_tab = NULL;
	size_t num_syms = 0;
	size_t sh_end = 0;
	const char *str_tab = NULL;
	size_t str_tab_size = 0;

	assert(shdr[rel_sidx].sh_type == SHT_RELA);

	assert(shdr[rel_sidx].sh_entsize == sizeof(Elf64_Rela));

	sym_tab_idx = shdr[rel_sidx].sh_link;
	if (sym_tab_idx) {
		size_t str_tab_idx = 0;

		if (sym_tab_idx >= elf->e_shnum)
			err(TEE_ERROR_GENERIC, "Symtab index out of range");

		assert(shdr[sym_tab_idx].sh_entsize == sizeof(Elf64_Sym));

		/* Check the address is inside TA memory */
		if (ADD_OVERFLOW(shdr[sym_tab_idx].sh_addr,
				 shdr[sym_tab_idx].sh_size, &sh_end))
			err(TEE_ERROR_SECURITY, "Overflow");
		if (sh_end >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_GENERIC, "Symbol table out of range");

		sym_tab = (Elf64_Sym *)(elf->load_addr +
					shdr[sym_tab_idx].sh_addr);

		num_syms = shdr[sym_tab_idx].sh_size / sizeof(Elf64_Sym);

		str_tab_idx = shdr[sym_tab_idx].sh_link;
		if (str_tab_idx) {
			/* Check the address is inside ELF memory */
			if (ADD_OVERFLOW(shdr[str_tab_idx].sh_addr,
					 shdr[str_tab_idx].sh_size, &sh_end))
				err(TEE_ERROR_SECURITY, "Overflow");
			if (sh_end >= (elf->max_addr - elf->load_addr))
				err(TEE_ERROR_GENERIC,
				    "String table out of range");

			str_tab = (const char *)(elf->load_addr +
						 shdr[str_tab_idx].sh_addr);
			str_tab_size = shdr[str_tab_idx].sh_size;
		}
	}

	/* Check the address is inside TA memory */
	if (ADD_OVERFLOW(shdr[rel_sidx].sh_addr,
			 shdr[rel_sidx].sh_size, &sh_end))
		err(TEE_ERROR_SECURITY, "Overflow");
	if (sh_end >= (elf->max_addr - elf->load_addr))
		err(TEE_ERROR_GENERIC, "Relocation table out of range");
	rela = (Elf64_Rela *)(elf->load_addr + shdr[rel_sidx].sh_addr);

	rela_end = rela + shdr[rel_sidx].sh_size / sizeof(Elf64_Rela);
	for (; rela < rela_end; rela++) {
		Elf64_Addr *where = NULL;
		size_t sym_idx = 0;

		/* Check the address is inside TA memory */
		if (rela->r_offset >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_GENERIC,
			    "Relocation offset out of range");

		where = (Elf64_Addr *)(elf->load_addr + rela->r_offset);

		switch (ELF64_R_TYPE(rela->r_info)) {
		case R_AARCH64_ABS64:
			sym_idx = ELF64_R_SYM(rela->r_info);
			if (sym_idx >= num_syms)
				err(TEE_ERROR_GENERIC,
				    "Symbol index out of range");
			if (sym_tab[sym_idx].st_shndx == SHN_UNDEF) {
				/* Symbol is external */
				e64_process_dyn_rela(sym_tab, num_syms, str_tab,
						     str_tab_size, rela, where);
			} else {
				*where = rela->r_addend + elf->load_addr +
					 sym_tab[sym_idx].st_value;
			}
			break;
		case R_AARCH64_RELATIVE:
			*where = rela->r_addend + elf->load_addr;
			break;
		case R_AARCH64_GLOB_DAT:
		case R_AARCH64_JUMP_SLOT:
			e64_process_dyn_rela(sym_tab, num_syms, str_tab,
					     str_tab_size, rela, where);
			break;
		default:
			err(TEE_ERROR_BAD_FORMAT, "Unknown relocation type %zd",
			     ELF64_R_TYPE(rela->r_info));
		}
	}
}
#else /*ARM64*/
static void __noreturn e64_relocate(struct ta_elf *elf __unused,
				    unsigned int rel_sidx __unused)
{
	err(TEE_ERROR_NOT_SUPPORTED, "arm64 not supported");
}
#endif /*ARM64*/

void ta_elf_relocate(struct ta_elf *elf)
{
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Shdr *shdr = elf->shdr;

		for (n = 0; n < elf->e_shnum; n++)
			if (shdr[n].sh_type == SHT_REL)
				e32_relocate(elf, n);
	} else {
		Elf64_Shdr *shdr = elf->shdr;

		for (n = 0; n < elf->e_shnum; n++)
			if (shdr[n].sh_type == SHT_RELA)
				e64_relocate(elf, n);

	}
}
