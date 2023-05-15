/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Arm Limited
 */

#include <ldelf.h>

/* macro	function name		syscall num		num of args */
LDELF_SYSCALL	_ldelf_return,		LDELF_RETURN,		1
LDELF_SYSCALL	_ldelf_log,		LDELF_LOG,		2
LDELF_SYSCALL	__ldelf_panic,		LDELF_PANIC,		1
LDELF_SYSCALL	_ldelf_map_zi,		LDELF_MAP_ZI,		6
LDELF_SYSCALL	_ldelf_unmap,		LDELF_UNMAP,		3
LDELF_SYSCALL	_ldelf_open_bin,	LDELF_OPEN_BIN,		3
LDELF_SYSCALL	_ldelf_close_bin,	LDELF_CLOSE_BIN,	1
LDELF_SYSCALL	_ldelf_map_bin,		LDELF_MAP_BIN,		8
LDELF_SYSCALL	_ldelf_cp_from_bin,	LDELF_CP_FROM_BIN,	4
LDELF_SYSCALL	_ldelf_set_prot,	LDELF_SET_PROT,		4
LDELF_SYSCALL	_ldelf_remap,		LDELF_REMAP,		7
LDELF_SYSCALL	_ldelf_gen_rnd_num,	LDELF_GEN_RND_NUM,	2
