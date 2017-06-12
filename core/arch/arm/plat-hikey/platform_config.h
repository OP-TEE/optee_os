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

/* PL011 UART */
#if defined(CFG_CONSOLE_UART) && (CFG_CONSOLE_UART == 0)
#define CONSOLE_UART_BASE       0xF8015000
#elif !defined(CFG_CONSOLE_UART) || (CFG_CONSOLE_UART == 3)
#define CONSOLE_UART_BASE       0xF7113000
#else
#error Unknown console UART
#endif

#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	19200000

/*
 * HiKey memory map
 *
 * TZDRAM is secured (firewalled) by the DDR controller, see ARM-TF, but note
 * that security of this type of memory is weak for two reasons:
 *   1. It is prone to physical tampering since DRAM is external to the SoC
 *   2. It is still somewhat prone to software attacks because the memory
 *      protection may be reverted by the non-secure kernel with a piece of
 *      code similar to the one that sets the protection in ARM-TF (we're
 *      missing a "lockdown" step which would prevent any change to the DDRC
 *      configuration until the next SoC reset).
 * TZSRAM is emulated in the TZDRAM area, because the on-chip SRAM of the SoC
 * is too small to run OP-TEE (72K total with 64K available, see "SRAM Memory
 * Region Layout" in ARM-TF plat/hikey/include/hisi_sram_map.h).
 *
 * CFG_WITH_PAGER=n
 *
 *  0x4000_0000                               -
 *    TA RAM: 15 MiB                          |
 *  0x3F10_0000                               | TZDRAM
 *    TEE RAM: 1 MiB (CFG_TEE_RAM_VA_SIZE)    |
 *  0x3F00_0000 [TZDRAM_BASE, BL32_LOAD_ADDR] -
 *    Shared memory: 2 MiB                    |
 *  0x3EE0_0000                               | DRAM0
 *    Reserved by UEFI for OP-TEE, unused     |
 *  0x3EC0_0000                               -
 *    Secure Data Path buffers: 4 MiB         | DRAM0 (secure)
 *  0x3E80_0000 [CFG_TEE_SDP_MEM_BASE]        -
 *    Reserved by UEFI for OP-TEE, unused     |
 *  0x3E00_0000                               | DRAM0
 *    Available to Linux                      |
 *  0x0000_0000 [DRAM0_BASE]                  -
 *
 * CFG_WITH_PAGER=y
 *
 *  0x4000_0000                               -
 *    TA RAM: 15 MiB                          | TZDRAM
 *  0x3F10_0000                               -
 *    Unused
 *  0x3F03_2000                               -
 *    TEE RAM: 200 KiB                        | TZSRAM
 *  0x3F00_0000 [TZSRAM_BASE, BL32_LOAD_ADDR] -
 *    Shared memory: 2 MiB                    |
 *  0x3EE0_0000                               | DRAM0
 *    Reserved by UEFI for OP-TEE, unused     |
 *  0x3EC0_0000                               -
 *    Secure Data Path buffers: 4 MiB         | DRAM0 (secure)
 *  0x3E80_0000 [CFG_TEE_SDP_MEM_BASE]        -
 *    Reserved by UEFI for OP-TEE, unused     |
 *  0x3E00_0000                               | DRAM0
 *    Available to Linux                      |
 *  0x0000_0000 [DRAM0_BASE]                  -
 */

#define DRAM0_BASE		0x00000000
#define DRAM0_SIZE		0x3F000000

#ifdef CFG_WITH_PAGER

#define TZSRAM_BASE		0x3F000000
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		0x3F100000
#define TZDRAM_SIZE		(15 * 1024 * 1024)

#else /* CFG_WITH_PAGER */

#define TZDRAM_BASE		0x3F000000
#define TZDRAM_SIZE		(16 * 1024 * 1024)

#endif /* CFG_WITH_PAGER */

#define CFG_SHMEM_START		0x3EE00000
#define CFG_SHMEM_SIZE		(2 * 1024 * 1024)

#define CFG_TEE_CORE_NB_CORE	8

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

#define CFG_TEE_LOAD_ADDR	0x3F000000

#ifdef CFG_WITH_PAGER

#define CFG_TEE_RAM_START	TZSRAM_BASE
#define CFG_TEE_RAM_PH_SIZE	TZSRAM_SIZE
#define CFG_TA_RAM_START	ROUNDUP(TZDRAM_BASE, CORE_MMU_DEVICE_SIZE)
#define CFG_TA_RAM_SIZE		ROUNDDOWN(TZDRAM_SIZE, CORE_MMU_DEVICE_SIZE)

#else /* CFG_WITH_PAGER */

#define CFG_TEE_RAM_PH_SIZE	CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	TZDRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP((TZDRAM_BASE + CFG_TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)

#define CFG_TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - CFG_TEE_RAM_VA_SIZE),\
					  CORE_MMU_DEVICE_SIZE)

#endif /* CFG_WITH_PAGER */

#endif /* PLATFORM_CONFIG_H */
