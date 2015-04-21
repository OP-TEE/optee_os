/*
 * Copyright (c) 2015, Linaro Limited
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

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM32
#define PLATFORM_LINKER_FORMAT	"elf32-littlearm"
#define PLATFORM_LINKER_ARCH	arm
#endif /*ARM32*/

/* PL011 UART */
#define CONSOLE_UART_BASE	0xF8015000
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	19200000

#define HEAP_SIZE		(24 * 1024)


#ifdef CFG_WITH_PAGER
#error "Pager not supported"
#endif

/*
 * HiKey memory map
 *
 *  0x4000_0000
 *    Secure DDR reserved for SCP use: 2 MiB
 *  0x3FE0_0000
 *    Secure DDR: 14 MiB
 *      0x3FE0_0000
 *        TA RAM: 13 MiB
 *      0x3F10_0000
 *        TEE RAM: 1 MiB (CFG_TEE_RAM_VA_SIZE)
 *  0x3F00_0000 [TZDRAM_BASE, BL32_LOAD_ADDR]
 *    Non-secure DDR (DRAM0): 1008 MiB
 *      0x3F00_0000
 *        Shared memory: 1 MiB
 *      0x3EF0_0000
 *        Available to Linux
 *  0x0000_0000 [DRAM0_BASE]
 */

#define DRAM0_BASE		0x00000000
#define DRAM0_SIZE		0x3F000000

#define TZDRAM_BASE		0x3F000000
#define TZDRAM_SIZE		0x00E00000

#define CFG_SHMEM_SIZE		0x100000
#define CFG_SHMEM_START		(DRAM0_BASE + DRAM0_SIZE - CFG_SHMEM_SIZE)

#define CFG_TEE_CORE_NB_CORE	8

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

/* Where ARM TF BL2 has loaded us */
#define BL32_LOAD_ADDR		0x3F000000
#define CFG_TEE_LOAD_ADDR	BL32_LOAD_ADDR

#define CFG_TEE_RAM_PH_SIZE	CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	TZDRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP((TZDRAM_BASE + CFG_TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)

#define CFG_TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - CFG_TEE_RAM_VA_SIZE),\
					  CORE_MMU_DEVICE_SIZE)

#define DEVICE0_BASE		ROUNDDOWN(CONSOLE_UART_BASE, \
					  CORE_MMU_DEVICE_SIZE)
#define DEVICE0_SIZE		CORE_MMU_DEVICE_SIZE

#endif /* PLATFORM_CONFIG_H */
