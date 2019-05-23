/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef TA_ELF_H
#define TA_ELF_H

#include <ldelf.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

struct segment {
	size_t offset;
	size_t vaddr;
	size_t filesz;
	size_t memsz;
	size_t flags;
	size_t align;
	bool remapped_writeable;
	TAILQ_ENTRY(segment) link;
};

TAILQ_HEAD(segment_head, segment);

struct ta_elf {
	bool is_main;
	bool is_32bit;	/* Initialized from Elf32_Ehdr/Elf64_Ehdr */
	bool is_legacy;

	vaddr_t load_addr;
	vaddr_t max_addr;
	vaddr_t max_offs;

	vaddr_t ehdr_addr;

	/* Initialized from Elf32_Ehdr/Elf64_Ehdr */
	vaddr_t e_entry;
	vaddr_t e_phoff;
	vaddr_t e_shoff;
	unsigned int e_phnum;
	unsigned int e_shnum;
	unsigned int e_phentsize;
	unsigned int e_shentsize;

	void *phdr;
	void *shdr;
	/*
	 * dynsymtab and dynstr are used for external symbols, they may hold
	 * other symbols too.
	 */
	void *dynsymtab;
	size_t num_dynsyms;
	const char *dynstr;
	size_t dynstr_size;

	struct segment_head segs;

	uint32_t handle;

	TEE_UUID uuid;
	TAILQ_ENTRY(ta_elf) link;
};

TAILQ_HEAD(ta_elf_queue, ta_elf);

extern struct ta_elf_queue main_elf_queue;

void ta_elf_load_main(const TEE_UUID *uuid, uint32_t *is_32bit,
		      uint64_t *entry, uint64_t *sp, uint32_t *ta_flags);
void ta_elf_load_dependency(struct ta_elf *elf, bool is_32bit);
void ta_elf_relocate(struct ta_elf *elf);
void ta_elf_finalize_mappings(struct ta_elf *elf);

void ta_elf_print_mappings(struct ta_elf_queue *elf_queue, size_t num_maps,
			   struct dump_map *maps, vaddr_t mpool_base);

#endif /*TA_ELF_H*/
