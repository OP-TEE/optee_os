/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Linaro limited
 */

#ifndef _DLFCN_H_
#define _DLFCN_H_

/* Relocations are performed when the object is loaded. */
#define RTLD_NOW	2
/* All symbols are available for relocation processing of other modules. */
#define RTLD_GLOBAL	0x100
/* Do not unload the shared object during dlclose(). */
#define RTLD_NODELETE	0x1000
/* Other flags are not supported */

/* Note: @flags must be (RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE) */
void *dlopen(const char *filename, int flags);
int dlclose(void *handle);
void *dlsym(void *handle, const char *symbol);

#endif /* _DLFCN_H_ */
