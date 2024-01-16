/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2021, Linaro Limited
 * Copyright (c) 2020-2023, Arm Limited
 */

#ifndef __KERNEL_USER_MODE_CTX_STRUCT_H
#define __KERNEL_USER_MODE_CTX_STRUCT_H

#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/tee_mmu_types.h>

/*
 * struct user_mode_ctx - user mode context
 * @vm_info:		Virtual memory map of this context
 * @regions:		Memory regions registered by pager
 * @vfp:		State of VFP registers
 * @keys:		Pointer authentication keys
 * @ts_ctx:		Generic TS context
 * @entry_func:		Entry address in TS
 * @dump_entry_func:	Entry address in TS for dumping address mappings
 *			and stack trace
 * @ftrace_entry_func:	Entry address in ldelf for dumping ftrace data
 * @dl_entry_func:	Entry address in ldelf for dynamic linking
 * @ldelf_stack_ptr:	Stack pointer used for dumping address mappings and
 *			stack trace
 * @is_32bit:		True if 32-bit TS, false if 64-bit TS
 * @is_initializing:	True if TS is not fully loaded
 * @stack_ptr:		Stack pointer
 * @bbuf:		Bounce buffer for user buffers
 * @bbuf_size:		Size of bounce buffer
 * @bbuf_offs:		Offset to unused part of bounce buffer
 */
struct user_mode_ctx {
	struct vm_info vm_info;
	struct vm_paged_region_head *regions;
	struct pgt_cache pgt_cache;
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
#if defined(CFG_TA_PAUTH)
	struct thread_pauth_keys keys;
#endif
	struct ts_ctx *ts_ctx;
	uaddr_t entry_func;
	uaddr_t load_addr;
	uaddr_t dump_entry_func;
#ifdef CFG_FTRACE_SUPPORT
	uaddr_t ftrace_entry_func;
#endif
	uaddr_t dl_entry_func;
	uaddr_t ldelf_stack_ptr;
	bool is_32bit;
	bool is_initializing;
	vaddr_t stack_ptr;
	uint8_t *bbuf;
	size_t bbuf_size;
	size_t bbuf_offs;
};
#endif /*__KERNEL_USER_MODE_CTX_STRUCT_H*/

