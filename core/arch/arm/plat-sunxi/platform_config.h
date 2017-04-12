/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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

#define STACK_ALIGNMENT		8

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform sunxi"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for platform sunxi"
#endif

#define GIC_BASE		0x01c40000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000
#define UART0_BASE		0x07000000
#define UART1_BASE		0x07000400
#define UART2_BASE		0x07000800
#define UART3_BASE		0x07000c00
#define CCI400_BASE             0x01c90000
#define SMC_BASE                0x01c0b000
#define PRCM_BASE               0x08001400

/* CCI-400 register defines */
#define CCI400_SECURE_ACCESS_REG  (0x8)

/* PRCM register defines */
#define PRCM_CPU_SOFT_ENTRY_REG   (0x164)

/* console uart define */
#define CONSOLE_UART_BASE       UART0_BASE

#define DRAM0_BASE		0x20000000
#define DRAM0_SIZE		0x80000000

/* Location of trusted dram on sunxi */
#define TZDRAM_BASE		0x9C000000
#define TZDRAM_SIZE		0x04000000

#define CFG_TEE_CORE_NB_CORE	8

#define DDR_PHYS_START		DRAM0_BASE
#define DDR_SIZE		DRAM0_SIZE

#define CFG_DDR_START		DDR_PHYS_START
#define CFG_DDR_SIZE		DDR_SIZE

#define CFG_DDR_TEETZ_RESERVED_START	TZDRAM_BASE
#define CFG_DDR_TEETZ_RESERVED_SIZE	TZDRAM_SIZE

#define TEE_RAM_START		(TZDRAM_BASE)
#define TEE_RAM_SIZE		(1 * 1024 * 1024)

/*
 * TEE/TZ RAM layout:
 *
 *  +-----------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEETZ private RAM  |  TEE_RAM           |   ^
 *  |                    +--------------------+   |
 *  |                    |  TA_RAM            |   |
 *  +-----------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |                    |      teecore alloc |   |
 *  |  TEE/TZ and NSec   |  PUB_RAM   --------|   |
 *  |   shared memory    |         NSec alloc |   |
 *  +-----------------------------------------+   v
 *
 *  TEE_RAM : 1MByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

/* define the several memory area sizes */
#if (CFG_DDR_TEETZ_RESERVED_SIZE < (4 * 1024 * 1024))
#error "Invalid CFG_DDR_TEETZ_RESERVED_SIZE: at least 4MB expected"
#endif

#define CFG_TEE_RAM_PH_SIZE		(1 * 1024 * 1024)
#define CFG_TEE_RAM_SIZE		CFG_TEE_RAM_PH_SIZE
#define CFG_TA_RAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
					CFG_TEE_RAM_SIZE - CFG_SHMEM_SIZE)

/* define the secure/unsecure memory areas */
#define CFG_DDR_ARMTZ_ONLY_START	(CFG_DDR_TEETZ_RESERVED_START)
#define CFG_DDR_ARMTZ_ONLY_SIZE		(CFG_TEE_RAM_SIZE + CFG_TA_RAM_SIZE)

#define CFG_DDR_ARM_ARMTZ_START		\
			(CFG_DDR_ARMTZ_ONLY_START + CFG_DDR_ARMTZ_ONLY_SIZE)
#define CFG_DDR_ARM_ARMTZ_SIZE		(CFG_PUB_RAM_SIZE)

/* define the memory areas (TEE_RAM must start at reserved DDR start addr */
#define CFG_TEE_RAM_START		(CFG_DDR_ARMTZ_ONLY_START)
#define CFG_TA_RAM_START		(CFG_TEE_RAM_START + CFG_TEE_RAM_SIZE)
#define CFG_PUB_RAM_START		(CFG_TA_RAM_START + CFG_TA_RAM_SIZE)

/* Full GlobalPlatform test suite requires CFG_SHMEM_SIZE to be at least 2MB */
#define CFG_SHMEM_START		(DDR_PHYS_START + 0x1000000)
#define CFG_SHMEM_SIZE		0x100000

#define CFG_TEE_LOAD_ADDR	TEE_RAM_START

#define AHB0_BASE		0x01400000
#define AHB0_SIZE		0x00900000

#define AHB1_BASE		0x00800000
#define AHB1_SIZE		0x00300000

#define AHB2_BASE		0x03000000
#define AHB2_SIZE		0x01000000

#define AHBS_BASE		0x06000000
#define AHBS_SIZE		0x02200000

#endif /*PLATFORM_CONFIG_H*/
