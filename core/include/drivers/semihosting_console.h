/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */
#ifndef __DRIVERS_SEMIHOSTING_CONSOLE_H
#define __DRIVERS_SEMIHOSTING_CONSOLE_H

#ifdef CFG_SEMIHOSTING_CONSOLE
/*
 * Initialize console which uses architecture-specific semihosting mechanism.
 * If @file_path is not NULL, OP-TEE OS will try to output log to that file,
 * which is on the semihosting host system.
 * Otherwise, if @file_path is NULL, OP-TEE OS will try to output log to the
 * semihosting host debug console.
 */
void semihosting_console_init(const char *file_path);
#else
static inline void semihosting_console_init(const char *file_path __unused)
{
}
#endif

#endif /* __DRIVERS_SEMIHOSTING_CONSOLE_H */
