/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2012 The Android Open Source Project
 */

#ifndef _LINK_H_
#define	_LINK_H_

#include <elf.h>
#include <stddef.h>

struct dl_phdr_info {
	Elf_Addr dlpi_addr;			/* module relocation base */
	const char *dlpi_name;			/* module name */
	const Elf_Phdr *dlpi_phdr;		/* pointer to module's phdr */
	Elf_Half dlpi_phnum;			/* number of entries in phdr */
	unsigned long long dlpi_adds;		/* total # of loads */
	unsigned long long dlpi_subs;		/* total # of unloads */
	size_t dlpi_tls_modid;
	void *dlpi_tls_data;
};

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size,
				    void *data),
		    void *data);

#endif /* _LINK_H_ */
