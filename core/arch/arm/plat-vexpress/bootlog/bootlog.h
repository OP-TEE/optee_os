/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 Devendra Devadiga.
 */

#ifndef BOOT_LOG_H
#define BOOT_LOG_H

#include <mm/core_memprot.h>
#include <io.h>

#define BOOT_LOG_SIG_OFFSET             0x0000
#define BOOT_LOG_SIG_OFFSET_SIZE        0x0004
#define BOOT_LOG_SIG_VAL                0xAA55AA55
#define BOOT_LOG_CUR_LEN_OFF            0x0004
#define BOOT_LOG_CUR_LEN_SIZE           0x0004
#define BOOT_LOG_HEADER_SIZE            0x0008
#define BOOT_LOG_MAX_SIZE		0xFFFF8U

/*
 * @base: Base address of memory where boot log will be saved.
 * @max_size: Max size of memory reserved for boot log message
 */
struct bootlog {
	struct io_pa_va base;
	uint32_t bootlog_max_size;
};

void boot_log_init(uintptr_t pa_base, uint32_t size);
void boot_log_putchar(char ch);

#endif /* BOOT_LOG_H */
