// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */
#include <ldelf.h>
#include <string.h>

#include "dl.h"
#include "ta_elf.h"

TEE_Result dlopen_entry(struct dl_entry_arg *arg)
{
	TEE_UUID zero = { };

	if (arg->dlopen.flags != (RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!memcmp(&arg->dlopen.uuid, &zero, sizeof(zero)))
		return TEE_SUCCESS;

	return ta_elf_add_library(&arg->dlopen.uuid);
}

TEE_Result dlsym_entry(struct dl_entry_arg *arg)
{
	struct ta_elf *elf = NULL;
	TEE_UUID zero = { };

	if (memcmp(&arg->dlsym.uuid, &zero, sizeof(zero))) {
		elf = ta_elf_find_elf(&arg->dlsym.uuid);
		if (!elf)
			return TEE_ERROR_ITEM_NOT_FOUND;
	}

	return ta_elf_resolve_sym(arg->dlsym.symbol, &arg->dlsym.val, NULL,
				  elf);
}

