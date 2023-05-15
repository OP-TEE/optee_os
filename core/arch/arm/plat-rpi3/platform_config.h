/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Sequitur Labs Inc. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported for ARM64"
#endif
#endif /* ARM64 */

/* 16550 UART */
#define CONSOLE_UART_BASE	0x3f215040 /* UART0 */
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	19200000

/*
 * RPi memory map
 *
 * No secure memory on RPi...
 *
 *
 *    Available to Linux <above>
 *  0x0a00_0000
 *    TA RAM: 16 MiB                          |
 *  0x0842_0000                               | TZDRAM
 *    TEE RAM: 4 MiB (TEE_RAM_VA_SIZE)	      |
 *  0x0840_0000 [ARM Trusted Firmware       ] -
 *  0x0840_0000 [TZDRAM_BASE, BL32_LOAD_ADDR] -
 *    Shared memory: 4 MiB                    |
 *  0x0800_0000                               | DRAM0
 *    Available to Linux                      |
 *  0x0000_0000 [DRAM0_BASE]                  -
 *
 */

#define DRAM0_BASE		0x00000000
#define DRAM0_SIZE		0x40000000

#endif /* PLATFORM_CONFIG_H */
