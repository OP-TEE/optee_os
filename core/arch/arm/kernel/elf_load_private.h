/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2018, Linaro Limited
 */
#ifndef _ELF_LOAD_PRIVATE_H_
#define _ELF_LOAD_PRIVATE_H_

#include <compiler.h>
#include <speculation_barrier.h>
#include <types_ext.h>
#include <tee_api_types.h>
#include "elf32.h"
#include "elf64.h"

struct user_ta_elf_head;

struct elf_load_state {
	bool is_32bit;
	bool is_main; /* false for a library */
	struct user_ta_elf_head *elfs; /* All ELFs, starting with main */

	struct user_ta_store_handle *ta_handle;
	const struct user_ta_store_ops *ta_store;
	size_t data_len;
	struct file *file;

	size_t next_offs;

	/* TA header info (is_main == true only) */
	void *ta_head;
	size_t ta_head_size;

	void *ehdr;
	void *phdr;

	size_t vasize;
	void *shdr;

	/* .dynamic section */
	void *dyn;
	size_t dyn_size;

	/* .dynstr section */
	char *dynstr;
	size_t dynstr_size;

	/* .dynsym section */
	void *dynsym;
	size_t dynsym_size;

	TEE_Result (*resolve_sym)(struct user_ta_elf_head *elfs,
				  const char *name, uintptr_t *val);
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

/* Replicates the fields we need from Elf{32,64}_Shdr */
struct elf_shdr {
	uint32_t sh_type;
	uintptr_t sh_addr;
	size_t sh_size;
};

/* Replicates the fields we need from Elf{32,64}_Dyn */
struct elf_dyn {
	int64_t d_tag;
	union {
		uint64_t d_val;
		uint64_t d_ptr;
	} d_un;
};

/* Replicates the fields we need from Elf{32,64}_Sym */
struct elf_sym {
	size_t st_name;
	uintptr_t st_value;
	uint16_t st_shndx;
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

static inline void copy_ehdr(struct elf_ehdr *ehdr,
			     struct elf_load_state *state)
{
	DO_ACTION(state, COPY_EHDR(ehdr, ((Elf32_Ehdr *)state->ehdr)),
			 COPY_EHDR(ehdr, ((Elf64_Ehdr *)state->ehdr)));
}

static inline uint32_t get_shdr_type(struct elf_load_state *state, size_t idx)
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

static inline void copy_phdr(struct elf_phdr *phdr,
			     struct elf_load_state *state, size_t idx)
{
	DO_ACTION(state, COPY_PHDR(phdr, ((Elf32_Phdr *)state->phdr + idx)),
			 COPY_PHDR(phdr, ((Elf64_Phdr *)state->phdr + idx)));
}

#define COPY_SHDR(dst, src) \
	do { \
		(dst)->sh_type = (src)->sh_type; \
		(dst)->sh_addr = (src)->sh_addr; \
		(dst)->sh_size = (src)->sh_size; \
	} while (0)

static inline void copy_shdr(struct elf_shdr *shdr,
			     size_t n,
			     struct elf_load_state *state)
{
	DO_ACTION(state, COPY_SHDR(shdr, ((Elf32_Shdr *)state->shdr + n)),
			 COPY_SHDR(shdr, ((Elf64_Shdr *)state->shdr + n)));
}

#define COPY_DYN(dst, src) \
	do { \
		(dst)->d_tag = (src)->d_tag; \
		(dst)->d_un.d_val = (src)->d_un.d_val; \
	} while (0)

static inline bool copy_dyn(struct elf_dyn *dyn,
				  size_t n,
				  struct elf_load_state *state)
{
	Elf32_Dyn *lower32 = (Elf32_Dyn *)state->dyn;
	Elf32_Dyn *dyn32 = (Elf32_Dyn *)state->dyn + n;
	Elf32_Dyn *upper32 = (Elf32_Dyn *)state->dyn +
			     state->dyn_size / sizeof(Elf32_Dyn);
	Elf64_Dyn *lower64 __maybe_unused = (Elf64_Dyn *)state->dyn;
	Elf64_Dyn *dyn64 __maybe_unused = (Elf64_Dyn *)state->dyn + n;
	Elf64_Dyn *upper64 __maybe_unused = (Elf64_Dyn *)state->dyn +
					state->dyn_size / sizeof(Elf64_Dyn);
	void *p;

	DO_ACTION(state, dyn32 = load_no_speculate_cmp(&dyn32, lower32, upper32,
						       NULL, dyn32); p = dyn32,
			 dyn64 = load_no_speculate_cmp(&dyn64, lower64, upper64,
						       NULL, dyn64); p = dyn64);
	if (!p)
		return false;
	DO_ACTION(state, COPY_DYN(dyn, dyn32), COPY_DYN(dyn, dyn64));
	return true;
}

#define COPY_SYM(dst, src) \
	do { \
		(dst)->st_name = (src)->st_name; \
		(dst)->st_value = (src)->st_value; \
		(dst)->st_shndx = (src)->st_shndx; \
	} while (0)

static inline bool copy_sym(struct elf_sym *sym,
			    size_t n,
			    struct elf_load_state *state)
{
	Elf32_Sym *lower32 = (Elf32_Sym *)state->dynsym;
	Elf32_Sym *sym32 = (Elf32_Sym *)state->dynsym + n;
	Elf32_Sym *upper32 = (Elf32_Sym *)state->dynsym +
			     state->dynsym_size / sizeof(Elf32_Sym);
	Elf64_Sym *lower64 __maybe_unused = (Elf64_Sym *)state->dynsym;
	Elf64_Sym *sym64 __maybe_unused = (Elf64_Sym *)state->dynsym + n;
	Elf64_Sym *upper64 __maybe_unused = (Elf64_Sym *)state->dynsym +
					state->dynsym_size / sizeof(Elf64_Sym);
	void *p;

	DO_ACTION(state, sym32 = load_no_speculate_cmp(&sym32, lower32, upper32,
						       NULL, sym32); p = sym32,
			 sym64 = load_no_speculate_cmp(&sym64, lower64, upper64,
						       NULL, sym64); p = sym64);
	if (!p)
		return false;
	DO_ACTION(state, COPY_SYM(sym, sym32), COPY_SYM(sym, sym64));
	return true;
}
#endif /* _ELF_LOAD_PRIVATE_H_ */
