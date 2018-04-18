/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2018, Linaro Limited
 */
#ifndef _ELF_LOAD_PRIVATE_H_
#define _ELF_LOAD_PRIVATE_H_

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

#endif /* _ELF_LOAD_PRIVATE_H_ */
