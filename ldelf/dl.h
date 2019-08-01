/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef LDELF_DL_H
#define LDELF_DL_H

#include <types_ext.h>
#include <ldelf.h>

TEE_Result dlopen_entry(struct dl_entry_arg *arg);
TEE_Result dlsym_entry(struct dl_entry_arg *arg);

#endif /*LDELF_DL_H*/

