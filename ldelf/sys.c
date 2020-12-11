// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <ldelf.h>
#include <trace.h>

#include "sys.h"

int trace_level = TRACE_LEVEL;
const char trace_ext_prefix[]  = "LD";

void __panic(const char *file __maybe_unused, const int line __maybe_unused,
	     const char *func __maybe_unused)
{
	if (!file && !func)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic at %s:%d %s%s%s",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");

	_ldelf_panic(1);
	/*NOTREACHED*/
	while (true)
		;
}

void sys_return_cleanup(void)
{
	_ldelf_return(0);
	/*NOTREACHED*/
	while (true)
		;
}

TEE_Result sys_map_zi(size_t num_bytes, uint32_t flags, vaddr_t *va,
		      size_t pad_begin, size_t pad_end)
{
	return _ldelf_map_zi(va, num_bytes, pad_begin, pad_end, flags);
}

TEE_Result sys_unmap(vaddr_t va, size_t num_bytes)
{
	return _ldelf_unmap(va, num_bytes);
}

TEE_Result sys_open_ta_bin(const TEE_UUID *uuid, uint32_t *handle)
{
	return _ldelf_open_bin(uuid, sizeof(TEE_UUID), handle);
}

TEE_Result sys_close_ta_bin(uint32_t handle)
{
	return _ldelf_close_bin(handle);
}

TEE_Result sys_map_ta_bin(vaddr_t *va, size_t num_bytes, uint32_t flags,
			  uint32_t handle, size_t offs, size_t pad_begin,
			  size_t pad_end)
{
	return _ldelf_map_bin(va, num_bytes, handle, offs,
			     pad_begin, pad_end, flags);
}


TEE_Result sys_copy_from_ta_bin(void *dst, size_t num_bytes, uint32_t handle,
				size_t offs)
{
	return _ldelf_cp_from_bin(dst, offs, num_bytes, handle);
}

TEE_Result sys_set_prot(vaddr_t va, size_t num_bytes, uint32_t flags)
{
	return _ldelf_set_prot(va, num_bytes, flags);
}

TEE_Result sys_remap(vaddr_t old_va, vaddr_t *new_va, size_t num_bytes,
		     size_t pad_begin, size_t pad_end)
{
	return _ldelf_remap(old_va, new_va, num_bytes, pad_begin, pad_end);
}

TEE_Result sys_gen_random_num(void *buf, size_t blen)
{
	return _ldelf_gen_rnd_num(buf, blen);
}
