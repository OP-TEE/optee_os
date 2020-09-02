// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <confine_array_index.h>
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
			  vaddr_t *val, bool weak_ok)
{
	bool bind_ok = false;

	if (!st_name)
		return false;
	if (st_name > elf->dynstr_size)
		err(TEE_ERROR_BAD_FORMAT, "Symbol name out of range");
	if (strcmp(name, elf->dynstr + st_name))
		return false;
	if (st_bind == STB_GLOBAL || (weak_ok && st_bind == STB_WEAK))
		bind_ok = true;
	if (!bind_ok)
		return false;
	if (st_bind == STB_WEAK && st_shndx == SHN_UNDEF) {
		if (val)
			*val = 0;
		return true;
	}
	if (st_shndx == SHN_UNDEF || st_shndx == SHN_XINDEX)
		return false;

	switch (st_type) {
	case STT_NOTYPE:
	case STT_OBJECT:
	case STT_FUNC:
		if (st_value > (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_BAD_FORMAT,
			    "Symbol location out of range");
		if (val)
			*val = st_value + elf->load_addr;
		break;
	case STT_TLS:
		if (val)
			*val = st_value;
		break;
	default:
		err(TEE_ERROR_NOT_SUPPORTED, "Symbol type not supported");
	}

	return true;
}

static TEE_Result resolve_sym_helper(uint32_t hash, const char *name,
				     vaddr_t *val, struct ta_elf *elf,
				     bool weak_ok)
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
			/*
			 * We're loading values from sym[] which later
			 * will be used to load something.
			 * => Spectre V1 pattern, need to cap the index
			 * against speculation.
			 */
			n = confine_array_index(n, elf->num_dynsyms);
			if (__resolve_sym(elf,
					  ELF32_ST_BIND(sym[n].st_info),
					  ELF32_ST_TYPE(sym[n].st_info),
					  sym[n].st_shndx,
					  sym[n].st_name,
					  sym[n].st_value, name, val, weak_ok))
				return TEE_SUCCESS;
		}
	} else {
		Elf64_Sym *sym = elf->dynsymtab;

		for (n = bucket[hash % nbuckets]; n; n = chain[n]) {
			if (n >= nchains || n >= elf->num_dynsyms)
				err(TEE_ERROR_BAD_FORMAT,
				    "Index out of range");
			/*
			 * We're loading values from sym[] which later
			 * will be used to load something.
			 * => Spectre V1 pattern, need to cap the index
			 * against speculation.
			 */
			n = confine_array_index(n, elf->num_dynsyms);
			if (__resolve_sym(elf,
					  ELF64_ST_BIND(sym[n].st_info),
					  ELF64_ST_TYPE(sym[n].st_info),
					  sym[n].st_shndx,
					  sym[n].st_name,
					  sym[n].st_value, name, val, weak_ok))
				return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

/*
 * Look for named symbol in @elf, or all modules if @elf == NULL. Global symbols
 * are searched first, then weak ones. Last option, when at least one weak but
 * undefined symbol exists, resolve to zero. Otherwise return
 * TEE_ERROR_ITEM_NOT_FOUND.
 * @val (if != 0) receives the symbol value
 * @found_elf (if != 0) receives the module where the symbol is found
 */
TEE_Result ta_elf_resolve_sym(const char *name, vaddr_t *val,
			      struct ta_elf **found_elf,
			      struct ta_elf *elf)
{
	uint32_t hash = elf_hash(name);

	if (elf) {
		/* Search global symbols */
		if (!resolve_sym_helper(hash, name, val, elf,
					false /* !weak_ok */))
			goto success;
		/* Search weak symbols */
		if (!resolve_sym_helper(hash, name, val, elf,
					true /* weak_ok */))
			goto success;
	}

	TAILQ_FOREACH(elf, &main_elf_queue, link) {
		if (!resolve_sym_helper(hash, name, val, elf,
					false /* !weak_ok */))
			goto success;
		if (!resolve_sym_helper(hash, name, val, elf,
					true /* weak_ok */))
			goto success;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;

success:
	if (found_elf)
		*found_elf = elf;
	return TEE_SUCCESS;
}

static void e32_get_sym_name(const Elf32_Sym *sym_tab, size_t num_syms,
			     const char *str_tab, size_t str_tab_size,
			     Elf32_Rel *rel, const char **name)
{
	size_t sym_idx = 0;
	size_t name_idx = 0;

	sym_idx = ELF32_R_SYM(rel->r_info);
	if (sym_idx >= num_syms)
		err(TEE_ERROR_BAD_FORMAT, "Symbol index out of range");
	sym_idx = confine_array_index(sym_idx, num_syms);

	name_idx = sym_tab[sym_idx].st_name;
	if (name_idx >= str_tab_size)
		err(TEE_ERROR_BAD_FORMAT, "Name index out of range");
	*name = str_tab + name_idx;
}

static void resolve_sym(const char *name, vaddr_t *val, struct ta_elf **mod)
{
	TEE_Result res = ta_elf_resolve_sym(name, val, mod, NULL);

	if (res)
		err(res, "Symbol %s not found", name);
}

static void e32_process_dyn_rel(const Elf32_Sym *sym_tab, size_t num_syms,
				const char *str_tab, size_t str_tab_size,
				Elf32_Rel *rel, Elf32_Addr *where)
{
	const char *name = NULL;
	vaddr_t val = 0;

	e32_get_sym_name(sym_tab, num_syms, str_tab, str_tab_size, rel, &name);
	resolve_sym(name, &val, NULL);
	*where = val;
}

static void e32_tls_get_module(const Elf32_Sym *sym_tab, size_t num_syms,
			       const char *str_tab, size_t str_tab_size,
			       Elf32_Rel *rel, struct ta_elf **mod)
{
	const char *name = NULL;
	size_t sym_idx = 0;

	sym_idx = ELF32_R_SYM(rel->r_info);
	if (sym_idx >= num_syms)
		err(TEE_ERROR_BAD_FORMAT, "Symbol index out of range");
	sym_idx = confine_array_index(sym_idx, num_syms);
	if (!sym_idx || sym_tab[sym_idx].st_shndx != SHN_UNDEF) {
		/* No symbol, or symbol is defined in current module */
		return;
	}

	e32_get_sym_name(sym_tab, num_syms, str_tab, str_tab_size, rel, &name);
	resolve_sym(name, NULL, mod);
}

static void e32_tls_resolve(const Elf32_Sym *sym_tab, size_t num_syms,
			    const char *str_tab, size_t str_tab_size,
			    Elf32_Rel *rel, vaddr_t *val)
{
	const char *name = NULL;

	e32_get_sym_name(sym_tab, num_syms, str_tab, str_tab_size, rel, &name);
	resolve_sym(name, val, NULL);
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
			err(TEE_ERROR_BAD_FORMAT, "SYMTAB index out of range");
		sym_tab_idx = confine_array_index(sym_tab_idx, elf->e_shnum);

		assert(shdr[sym_tab_idx].sh_entsize == sizeof(Elf32_Sym));

		/* Check the address is inside ELF memory */
		if (ADD_OVERFLOW(shdr[sym_tab_idx].sh_addr,
				 shdr[sym_tab_idx].sh_size, &sh_end))
			err(TEE_ERROR_BAD_FORMAT, "Overflow");
		if (sh_end >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_BAD_FORMAT, "SYMTAB out of range");

		sym_tab = (Elf32_Sym *)(elf->load_addr +
					shdr[sym_tab_idx].sh_addr);

		num_syms = shdr[sym_tab_idx].sh_size / sizeof(Elf32_Sym);

		str_tab_idx = shdr[sym_tab_idx].sh_link;
		if (str_tab_idx) {
			if (str_tab_idx >= elf->e_shnum)
				err(TEE_ERROR_BAD_FORMAT,
				    "STRTAB index out of range");
			str_tab_idx = confine_array_index(str_tab_idx,
							  elf->e_shnum);

			/* Check the address is inside ELF memory */
			if (ADD_OVERFLOW(shdr[str_tab_idx].sh_addr,
					 shdr[str_tab_idx].sh_size, &sh_end))
				err(TEE_ERROR_BAD_FORMAT, "Overflow");
			if (sh_end >= (elf->max_addr - elf->load_addr))
				err(TEE_ERROR_BAD_FORMAT,
				    "STRTAB out of range");

			str_tab = (const char *)(elf->load_addr +
						 shdr[str_tab_idx].sh_addr);
			str_tab_size = shdr[str_tab_idx].sh_size;
		}
	}

	/* Check the address is inside TA memory */
	if (ADD_OVERFLOW(shdr[rel_sidx].sh_addr,
			 shdr[rel_sidx].sh_size, &sh_end))
		err(TEE_ERROR_BAD_FORMAT, "Overflow");
	if (sh_end >= (elf->max_addr - elf->load_addr))
		err(TEE_ERROR_BAD_FORMAT, ".rel.*/REL out of range");
	rel = (Elf32_Rel *)(elf->load_addr + shdr[rel_sidx].sh_addr);

	rel_end = rel + shdr[rel_sidx].sh_size / sizeof(Elf32_Rel);
	for (; rel < rel_end; rel++) {
		struct ta_elf *mod = NULL;
		Elf32_Addr *where = NULL;
		size_t sym_idx = 0;
		vaddr_t val = 0;

		/* Check the address is inside TA memory */
		if (rel->r_offset >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_BAD_FORMAT,
			    "Relocation offset out of range");
		where = (Elf32_Addr *)(elf->load_addr + rel->r_offset);

		switch (ELF32_R_TYPE(rel->r_info)) {
		case R_ARM_NONE:
			/*
			 * One would expect linker prevents such useless entry
			 * in the relocation table. We still handle this type
			 * here in case such entries exist.
			 */
			break;
		case R_ARM_ABS32:
			sym_idx = ELF32_R_SYM(rel->r_info);
			if (sym_idx >= num_syms)
				err(TEE_ERROR_BAD_FORMAT,
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
				err(TEE_ERROR_BAD_FORMAT,
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
		case R_ARM_TLS_DTPMOD32:
			mod = elf;
			e32_tls_get_module(sym_tab, num_syms, str_tab,
					   str_tab_size, rel, &mod);
			*where = mod->tls_mod_id;
			break;
		case R_ARM_TLS_DTPOFF32:
			e32_tls_resolve(sym_tab, num_syms, str_tab,
					str_tab_size, rel, &val);
			*where = val;
			break;
		default:
			err(TEE_ERROR_BAD_FORMAT, "Unknown relocation type %d",
			     ELF32_R_TYPE(rel->r_info));
		}
	}
}

#ifdef ARM64
static void e64_get_sym_name(const Elf64_Sym *sym_tab, size_t num_syms,
			     const char *str_tab, size_t str_tab_size,
			     Elf64_Rela *rela, const char **name)
{
	size_t sym_idx = 0;
	size_t name_idx = 0;

	sym_idx = ELF64_R_SYM(rela->r_info);
	if (sym_idx >= num_syms)
		err(TEE_ERROR_BAD_FORMAT, "Symbol index out of range");
	sym_idx = confine_array_index(sym_idx, num_syms);

	name_idx = sym_tab[sym_idx].st_name;
	if (name_idx >= str_tab_size)
		err(TEE_ERROR_BAD_FORMAT, "Name index out of range");
	*name = str_tab + name_idx;
}

static void e64_process_dyn_rela(const Elf64_Sym *sym_tab, size_t num_syms,
				 const char *str_tab, size_t str_tab_size,
				 Elf64_Rela *rela, Elf64_Addr *where)
{
	const char *name = NULL;
	uintptr_t val = 0;

	e64_get_sym_name(sym_tab, num_syms, str_tab, str_tab_size, rela, &name);
	resolve_sym(name, &val, NULL);
	*where = val;
}

static void e64_process_tls_tprel_rela(const Elf64_Sym *sym_tab,
				       size_t num_syms, const char *str_tab,
				       size_t str_tab_size, Elf64_Rela *rela,
				       Elf64_Addr *where, struct ta_elf *elf)
{
	struct ta_elf *mod = NULL;
	const char *name = NULL;
	size_t sym_idx = 0;
	vaddr_t symval = 0;

	sym_idx = ELF64_R_SYM(rela->r_info);
	if (sym_idx) {
		e64_get_sym_name(sym_tab, num_syms, str_tab, str_tab_size, rela,
				 &name);
		resolve_sym(name, &symval, &mod);
	} else {
		mod = elf;
	}
	*where = symval + mod->tls_tcb_offs + rela->r_addend;
}

struct tlsdesc {
	long (*resolver)(struct tlsdesc *td);
	long value;
};

/* Helper function written in assembly due to the calling convention */
long tlsdesc_resolve(struct tlsdesc *td);

static void e64_process_tlsdesc_rela(const Elf64_Sym *sym_tab, size_t num_syms,
				     const char *str_tab, size_t str_tab_size,
				     Elf64_Rela *rela, Elf64_Addr *where,
				     struct ta_elf *elf)
{
	/*
	 * @where points to a pair of 64-bit words in the GOT or PLT which is
	 * mapped to a struct tlsdesc:
	 *
	 * - resolver() must return the offset of the thread-local variable
	 *   relative to TPIDR_EL0.
	 * - value is implementation-dependent. The TLS_TPREL handling code is
	 *   re-used to get the desired offset so that tlsdesc_resolve() just
	 *   needs to return this value.
	 *
	 * Both the TA and ldelf are AArch64 so it is OK to point to a function
	 * in ldelf.
	 */
	*where = (Elf64_Addr)tlsdesc_resolve;
	e64_process_tls_tprel_rela(sym_tab, num_syms, str_tab, str_tab_size,
				   rela, where + 1, elf);
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
			err(TEE_ERROR_BAD_FORMAT, "SYMTAB index out of range");
		sym_tab_idx = confine_array_index(sym_tab_idx, elf->e_shnum);

		assert(shdr[sym_tab_idx].sh_entsize == sizeof(Elf64_Sym));

		/* Check the address is inside TA memory */
		if (ADD_OVERFLOW(shdr[sym_tab_idx].sh_addr,
				 shdr[sym_tab_idx].sh_size, &sh_end))
			err(TEE_ERROR_BAD_FORMAT, "Overflow");
		if (sh_end >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_BAD_FORMAT, "SYMTAB out of range");

		sym_tab = (Elf64_Sym *)(elf->load_addr +
					shdr[sym_tab_idx].sh_addr);

		num_syms = shdr[sym_tab_idx].sh_size / sizeof(Elf64_Sym);

		str_tab_idx = shdr[sym_tab_idx].sh_link;
		if (str_tab_idx) {
			if (str_tab_idx >= elf->e_shnum)
				err(TEE_ERROR_BAD_FORMAT,
				    "STRTAB index out of range");
			str_tab_idx = confine_array_index(str_tab_idx,
							  elf->e_shnum);

			/* Check the address is inside ELF memory */
			if (ADD_OVERFLOW(shdr[str_tab_idx].sh_addr,
					 shdr[str_tab_idx].sh_size, &sh_end))
				err(TEE_ERROR_BAD_FORMAT, "Overflow");
			if (sh_end >= (elf->max_addr - elf->load_addr))
				err(TEE_ERROR_BAD_FORMAT,
				    "STRTAB out of range");

			str_tab = (const char *)(elf->load_addr +
						 shdr[str_tab_idx].sh_addr);
			str_tab_size = shdr[str_tab_idx].sh_size;
		}
	}

	/* Check the address is inside TA memory */
	if (ADD_OVERFLOW(shdr[rel_sidx].sh_addr,
			 shdr[rel_sidx].sh_size, &sh_end))
		err(TEE_ERROR_BAD_FORMAT, "Overflow");
	if (sh_end >= (elf->max_addr - elf->load_addr))
		err(TEE_ERROR_BAD_FORMAT, ".rel.*/REL out of range");
	rela = (Elf64_Rela *)(elf->load_addr + shdr[rel_sidx].sh_addr);

	rela_end = rela + shdr[rel_sidx].sh_size / sizeof(Elf64_Rela);
	for (; rela < rela_end; rela++) {
		Elf64_Addr *where = NULL;
		size_t sym_idx = 0;

		/* Check the address is inside TA memory */
		if (rela->r_offset >= (elf->max_addr - elf->load_addr))
			err(TEE_ERROR_BAD_FORMAT,
			    "Relocation offset out of range");

		where = (Elf64_Addr *)(elf->load_addr + rela->r_offset);

		switch (ELF64_R_TYPE(rela->r_info)) {
		case R_AARCH64_NONE:
			/*
			 * One would expect linker prevents such useless entry
			 * in the relocation table. We still handle this type
			 * here in case such entries exist.
			 */
			break;
		case R_AARCH64_ABS64:
			sym_idx = ELF64_R_SYM(rela->r_info);
			if (sym_idx >= num_syms)
				err(TEE_ERROR_BAD_FORMAT,
				    "Symbol index out of range");
			sym_idx = confine_array_index(sym_idx, num_syms);
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
		case R_AARCH64_TLS_TPREL:
			e64_process_tls_tprel_rela(sym_tab, num_syms, str_tab,
						   str_tab_size, rela, where,
						   elf);
			break;
		case R_AARCH64_TLSDESC:
			e64_process_tlsdesc_rela(sym_tab, num_syms, str_tab,
						 str_tab_size, rela, where,
						 elf);
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
