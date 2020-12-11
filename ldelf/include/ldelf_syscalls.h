/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Arm Limited
 */

#ifndef LDELF_SYSCALLS_H
#define LDELF_SYSCALLS_H

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

void _ldelf_return(unsigned long ret) __noreturn;
void _ldelf_log(const void *buf, size_t len);
void _ldelf_panic(unsigned long code);
TEE_Result _ldelf_map_zi(vaddr_t *va, size_t num_bytes, size_t pad_begin,
			 size_t pad_end, unsigned long flags);
TEE_Result _ldelf_unmap(vaddr_t va, size_t num_bytes);
TEE_Result _ldelf_open_bin(const TEE_UUID *uuid, size_t uuid_size,
			   uint32_t *handle);
TEE_Result _ldelf_close_bin(unsigned long handle);
TEE_Result _ldelf_map_bin(vaddr_t *va, size_t num_bytes, unsigned long handle,
			  size_t offs, size_t pad_begin, size_t pad_end,
			  unsigned long flags);
TEE_Result _ldelf_cp_from_bin(void *dst, size_t offs, size_t num_bytes,
			      unsigned long handle);
TEE_Result _ldelf_set_prot(unsigned long va, size_t num_bytes,
			   unsigned long flags);
TEE_Result _ldelf_remap(unsigned long old_va, vaddr_t *new_va, size_t num_bytes,
			size_t pad_begin, size_t pad_end);
TEE_Result _ldelf_gen_rnd_num(void *buf, size_t num_bytes);

#endif /* LDELF_SYSCALLS_H */
