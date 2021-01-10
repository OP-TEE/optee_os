/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2021, Linaro Limited
 * Copyright (c) 2020, Arm Limited
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
 */
struct user_mode_ctx {
	struct vm_info vm_info;
	struct vm_paged_region_head *regions;
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct ts_ctx *ts_ctx;
	uaddr_t entry_func;
	uaddr_t dump_entry_func;
#ifdef CFG_FTRACE_SUPPORT
	uaddr_t ftrace_entry_func;
#endif
	uaddr_t dl_entry_func;
	uaddr_t ldelf_stack_ptr;
	bool is_32bit;
	bool is_initializing;
	vaddr_t stack_ptr;
};
#endif /*__KERNEL_USER_MODE_CTX_STRUCT_H*/

