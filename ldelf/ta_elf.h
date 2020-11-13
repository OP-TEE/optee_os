/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef TA_ELF_H
#define TA_ELF_H

#include <ldelf.h>
#include <stdarg.h>
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

	/* DT_HASH hash table for faster resolution of external symbols */
	void *hashtab;

	/* DT_SONAME */
	char *soname;

	struct segment_head segs;

	vaddr_t exidx_start;
	size_t exidx_size;

	/* Thread Local Storage */

	size_t tls_mod_id;
	/* PT_TLS segment */
	vaddr_t tls_start;
	size_t tls_filesz; /* Covers the .tdata section */
	size_t tls_memsz; /* Covers the .tdata and .tbss sections */
#ifdef ARM64
	/* Offset of the copy of the TLS block in the TLS area of the TCB */
	size_t tls_tcb_offs;
#endif

	uint32_t handle;

	struct ta_head *head;

	TEE_UUID uuid;
	TAILQ_ENTRY(ta_elf) link;
};

TAILQ_HEAD(ta_elf_queue, ta_elf);

typedef void (*print_func_t)(void *pctx, const char *fmt, va_list ap)
	__printf(2, 0);

extern struct ta_elf_queue main_elf_queue;
struct ta_elf *ta_elf_find_elf(const TEE_UUID *uuid);

void ta_elf_load_main(const TEE_UUID *uuid, uint32_t *is_32bit, uint64_t *sp,
		      uint32_t *ta_flags);
void ta_elf_finalize_load_main(uint64_t *entry);
void ta_elf_load_dependency(struct ta_elf *elf, bool is_32bit);
void ta_elf_relocate(struct ta_elf *elf);
void ta_elf_finalize_mappings(struct ta_elf *elf);

void ta_elf_print_mappings(void *pctx, print_func_t print_func,
			   struct ta_elf_queue *elf_queue, size_t num_maps,
			   struct dump_map *maps, vaddr_t mpool_base);

#ifdef CFG_UNWIND
void ta_elf_stack_trace_a32(uint32_t regs[16]);
void ta_elf_stack_trace_a64(uint64_t fp, uint64_t sp, uint64_t pc);
#else
static inline void ta_elf_stack_trace_a32(uint32_t regs[16] __unused) { }
static inline void ta_elf_stack_trace_a64(uint64_t fp __unused,
					  uint64_t sp __unused,
					  uint64_t pc __unused) { }
#endif /*CFG_UNWIND*/

TEE_Result ta_elf_resolve_sym(const char *name, vaddr_t *val,
			      struct ta_elf **found_elf, struct ta_elf *elf);
TEE_Result ta_elf_add_library(const TEE_UUID *uuid);
TEE_Result ta_elf_set_init_fini_info_compat(bool is_32bit);
TEE_Result ta_elf_set_elf_phdr_info(bool is_32bit);

#endif /*TA_ELF_H*/
