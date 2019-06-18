/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __LDELF_H
#define __LDELF_H

#include <types_ext.h>
#include <tee_api_types.h>

/* Size of stack for TEE Core to allocate */
#define LDELF_STACK_SIZE	(4096 * 2)

/*
 * struct ldelf_arg - argument for ldelf
 * @uuid:	  [in] UUID of TA to load
 * @is_32bit:	  [out] 1 if a 32bit TA or 0 if a 64bit TA
 * @flags:	  [out] Flags field of TA header
 * @entry_func:	  [out] TA entry function
 * @stack_ptr:	  [out] TA stack pointer
 * @dump_entry:	  [out] Dump TA mappings and stack trace
 * @ftrace_entry: [out] Dump TA mappings and ftrace buffer
 */
struct ldelf_arg {
	TEE_UUID uuid;
	uint32_t is_32bit;
	uint32_t flags;
	uint64_t entry_func;
	uint64_t stack_ptr;
	uint64_t dump_entry;
	uint64_t ftrace_entry;
};

#define DUMP_MAP_READ	BIT(0)
#define DUMP_MAP_WRITE	BIT(1)
#define DUMP_MAP_EXEC	BIT(2)
#define DUMP_MAP_SECURE	BIT(3)
#define DUMP_MAP_EPHEM	BIT(4)
#define DUMP_MAP_LDELF	BIT(7)

/*
 * struct dump_entry_arg - argument for ldelf_dump()
 */
struct dump_entry_arg {
	union {
		struct {
			uint32_t regs[16];
		} arm32;
		struct {
			uint64_t fp;
			uint64_t sp;
			uint64_t pc;
		} arm64;
	};
	bool is_arm32;
	size_t num_maps;
	struct dump_map {
		vaddr_t va;
		paddr_t pa;
		size_t sz;
		uint32_t flags;
	} maps[];
};

/*
 * ldelf is loaded into memory by TEE Core. BSS is initialized and a
 * stack is allocated and supplied in SP register. A struct ldelf_arg
 * is placed in the stack and a pointer to the struct is provided in
 * r0/x0.
 *
 * ldelf relocates itself to the address where it is loaded before the main
 * C routine is called.
 *
 * In the main C routine the TA is loaded using the PTA System interface.
 */

#endif /*__LDELF_H*/
