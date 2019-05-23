/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2019, Linaro Limited
 */
#ifndef ELF_LOAD_H
#define ELF_LOAD_H

#include <mm/file.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <kernel/user_ta_store.h>

struct file;
struct elf_load_state;
struct user_ta_elf_head;

TEE_Result elf_load_init(const struct user_ta_store_ops *ta_store,
			 struct user_ta_store_handle *ta_handle, bool is_main,
			 struct user_ta_elf_head *elfs,
			 TEE_Result (*resolve_sym)(struct user_ta_elf_head *,
						   const char *, uintptr_t *),
			 struct elf_load_state **state);

TEE_Result elf_load_get_file(struct elf_load_state *state, struct file **file);

TEE_Result elf_load_head(struct elf_load_state *state, size_t head_size,
			void **head, size_t *vasize, bool *is_32bit,
			vaddr_t *entry);
TEE_Result elf_load_body(struct elf_load_state *state, vaddr_t vabase);
TEE_Result elf_load_get_next_segment(struct elf_load_state *state, size_t *idx,
			vaddr_t *vaddr, size_t *size, uint32_t *flags,
			uint32_t *type);
TEE_Result elf_process_rel(struct elf_load_state *state, vaddr_t vabase);
void elf_load_final(struct elf_load_state *state);

#endif /*ELF_LOAD_H*/
