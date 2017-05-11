/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef ELF_LOAD_H
#define ELF_LOAD_H

#include <types_ext.h>
#include <tee_api_types.h>

struct elf_load_state;

struct user_ta_store_handle;
struct user_ta_store_ops {
	/*
	 * Open a TA. Does not guarantee that the TA is valid or even exists.
	 */
	TEE_Result (*open)(const TEE_UUID *uuid,
			   struct user_ta_store_handle **h);
	/*
	 * Return the size of the unencrypted TA binary, that is: the TA
	 * header (struct ta_head) plus the ELF data.
	 */
	TEE_Result (*get_size)(const struct user_ta_store_handle *h,
			       size_t *size);
	/*
	 * Read the TA sequentially, from the start of the TA header (struct
	 * ta_head) up to the end of the ELF.
	 * The TEE core is expected to read *exactly* get_size() bytes in total
	 * unless an error occurs. Therefore, an implementation may rely on the
	 * condition (current offset == total size) to detect the last call to
	 * this function.
	 * @data: pointer to secure memory where the TA bytes should be copied.
	 * If @data == NULL and @len != 0, the function should just skip @len
	 * bytes.
	 */
	TEE_Result (*read)(struct user_ta_store_handle *h, void *data,
			   size_t len);
	/*
	 * Close a TA handle. Do nothing if @h == NULL.
	 */
	void (*close)(struct user_ta_store_handle *h);
};

TEE_Result elf_load_init(const struct user_ta_store_ops *ta_store,
			 struct user_ta_store_handle *ta_handle,
			 struct elf_load_state **state);
TEE_Result elf_load_head(struct elf_load_state *state, size_t head_size,
			void **head, size_t *vasize, bool *is_32bit);
TEE_Result elf_load_body(struct elf_load_state *state, vaddr_t vabase);
TEE_Result elf_load_get_next_segment(struct elf_load_state *state, size_t *idx,
			vaddr_t *vaddr, size_t *size, uint32_t *flags,
			uint32_t *type);
void elf_load_final(struct elf_load_state *state);

#endif /*ELF_LOAD_H*/
