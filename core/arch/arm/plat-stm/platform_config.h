/*
 * Copyright (c) 2014, Linaro Limited
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

#define PLATFORM_FLAVOR_ID_orly2	0
#define PLATFORM_FLAVOR_ID_cannes	1
#define PLATFORM_FLAVOR_IS(flav) \
	(PLATFORM_FLAVOR == PLATFORM_FLAVOR_ID_ ## flav)

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		32

#define CFG_TEE_CORE_NB_CORE	2

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform STM"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for platform STM"
#endif

#define HEAP_SIZE		(24 * 1024)

/*
 * TEE/TZ RAM layout:
 *
 *  +---------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEETZ private RAM  |  TEE_RAM         |   ^
 *  |                    +------------------+   |
 *  |                    |  TA_RAM          |   |
 *  +---------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |                    |    teecore alloc |   |
 *  |  TEE/TZ and NSec   |  PUB_RAM   ------|   |
 *  |   shared memory    |       NSec alloc |   |
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : 1MByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

/* define the several memory area sizes */
#if (CFG_DDR_TEETZ_RESERVED_SIZE < (4 * 1024 * 1024))
#error "Invalid CFG_DDR_TEETZ_RESERVED_SIZE: at least 4MB expected"
#endif

#define CFG_SHMEM_SIZE		(2 * 1024 * 1024)
#define CFG_TEE_RAM_PH_SIZE	(1 * 1024 * 1024)
#define CFG_TA_RAM_SIZE		(CFG_DDR_TEETZ_RESERVED_SIZE - \
				 CFG_TEE_RAM_PH_SIZE - CFG_SHMEM_SIZE)

/* define the secure memory area */
#define TZDRAM_BASE		(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE		(CFG_TEE_RAM_PH_SIZE + CFG_TA_RAM_SIZE)

/* define the memory areas (TEE_RAM must start at reserved DDR start addr */
#define CFG_TEE_RAM_START	(TZDRAM_BASE)
#define CFG_TA_RAM_START	(CFG_TEE_RAM_START + CFG_TEE_RAM_PH_SIZE)
#define CFG_SHMEM_START		(CFG_TA_RAM_START + CFG_TA_RAM_SIZE)

#if PLATFORM_FLAVOR_IS(cannes)

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		0x80000000

#define CPU_IOMEM_BASE		0x08760000
#define CPU_PORT_FILT_START	0x40000000
#define CPU_PORT_FILT_END	0xC0000000
#define STXHxxx_LPM_PERIPH_BASE	0x09400000
#define ASC_NUM			20
#define UART_CONSOLE_BASE	ST_ASC20_REGS_BASE
#define RNG_BASE		0x08A89000

#elif PLATFORM_FLAVOR_IS(orly2)

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		0x40000000
#define DRAM1_BASE		0x80000000
#define DRAM1_SIZE		0x40000000

#define CPU_IOMEM_BASE		0xFFFE0000
#define CPU_PORT_FILT_START	0x40000000
#define CPU_PORT_FILT_END	0x80000000
#define STXHxxx_LPM_PERIPH_BASE	0xFE400000
#define ASC_NUM			21
#define UART_CONSOLE_BASE	ST_ASC21_REGS_BASE
#define RNG_BASE		0xFEE80000

#else

#error "Unknown platform flavor"

#endif

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
#endif


#define PL310_BASE		(CPU_IOMEM_BASE + 0x2000)
#define GIC_DIST_BASE		(CPU_IOMEM_BASE + 0x1000)
#define SCU_BASE		(CPU_IOMEM_BASE + 0x0000)
#define GIC_CPU_BASE		(CPU_IOMEM_BASE + 0x0100)
#define ST_ASC20_REGS_BASE	(STXHxxx_LPM_PERIPH_BASE + 0x00130000)
#define ST_ASC21_REGS_BASE	(STXHxxx_LPM_PERIPH_BASE + 0x00131000)

#define DEVICE0_PA_BASE		ROUNDDOWN(CPU_IOMEM_BASE, \
					  CORE_MMU_DEVICE_SIZE)
#define DEVICE0_VA_BASE		DEVICE0_PA_BASE
#define DEVICE0_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE0_TYPE		MEM_AREA_IO_NSEC

#define DEVICE1_PA_BASE		ROUNDDOWN(UART_CONSOLE_BASE, \
					  CORE_MMU_DEVICE_SIZE)
#define DEVICE1_VA_BASE		DEVICE1_PA_BASE
#define DEVICE1_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE1_TYPE		MEM_AREA_IO_NSEC

#define DEVICE2_PA_BASE		ROUNDDOWN(RNG_BASE, \
					  CORE_MMU_DEVICE_SIZE)
#define DEVICE2_VA_BASE		DEVICE2_PA_BASE
#define DEVICE2_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE2_TYPE		MEM_AREA_IO_SEC

#endif /*PLATFORM_CONFIG_H*/
