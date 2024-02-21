/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */
#ifndef __KERNEL_SEMIHOSTING_H
#define __KERNEL_SEMIHOSTING_H

#include <stddef.h>
#include <stdint.h>
#include <sys/fcntl.h>
#include <util.h>

/* Perform architecture-specific semihosting instructions. */
uintptr_t __do_semihosting(uintptr_t op, uintptr_t arg);

char semihosting_sys_readc(void);
void semihosting_sys_writec(char c);
int semihosting_open(const char *fname, int flags);
size_t semihosting_read(int fd, void *ptr, size_t len);
size_t semihosting_write(int fd, const void *ptr, size_t len);
int semihosting_close(int fd);

#endif /* __KERNEL_SEMIHOSTING_H */
