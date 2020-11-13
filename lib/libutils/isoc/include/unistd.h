/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef UNISTD_H
#define UNISTD_H

#include <stdint.h>
#include <stddef.h>

#define __ssize_t_defined
typedef intptr_t ssize_t;

/* @fd must be 1 or 2. Writes to the secure console. */
ssize_t write(int fd, const void *buf, size_t count);

#endif
