/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <kernel/handle.h>
#include <kernel/ts_store.h>
#include <kernel/user_mode_ctx_struct.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#ifndef __KERNEL_LDELF_SYSCALLS_H
#define __KERNEL_LDELF_SYSCALLS_H

struct system_ctx {
	struct handle_db db;
	const struct ts_store_ops *store_op;
};

TEE_Result ldelf_syscall_map_zi(vaddr_t *va, size_t num_bytes, size_t pad_begin,
				size_t pad_end, unsigned long flags);
TEE_Result ldelf_syscall_unmap(vaddr_t va, size_t num_bytes);
TEE_Result ldelf_syscall_open_bin(const TEE_UUID *uuid, size_t uuid_size,
				  uint32_t *handle);
TEE_Result ldelf_syscall_close_bin(unsigned long handle);
TEE_Result ldelf_syscall_map_bin(vaddr_t *va, size_t num_bytes,
				 unsigned long handle, size_t offs_bytes,
				 size_t pad_begin, size_t pad_end,
				 unsigned long flags);
TEE_Result ldelf_syscall_copy_from_bin(void *dst, size_t offs, size_t num_bytes,
				       unsigned long handle);
TEE_Result ldelf_syscall_set_prot(unsigned long va, size_t num_bytes,
				  unsigned long flags);
TEE_Result ldelf_syscall_remap(unsigned long old_va, vaddr_t *new_va,
			       size_t num_bytes, size_t pad_begin,
			       size_t pad_end);
TEE_Result ldelf_syscall_gen_rnd_num(void *buf, size_t num_bytes);
void ldelf_sess_cleanup(struct ts_session *sess);

#endif /* __KERNEL_LDELF_SYSCALLS_H */
