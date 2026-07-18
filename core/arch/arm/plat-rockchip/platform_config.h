/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 * Copyright (c) 2024, Rockchip, Inc. All rights reserved.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define SIZE_K(n)		((n) * 1024)
#define SIZE_M(n)		((n) * 1024 * 1024)

#if defined(PLATFORM_FLAVOR_rk322x)

#define GIC_BASE		0x32010000
#define GIC_SIZE		SIZE_K(64)
#define GICD_BASE		(GIC_BASE + 0x1000)
#define GICC_BASE		(GIC_BASE + 0x2000)

#define SGRF_BASE		0x10140000
#define SGRF_SIZE		SIZE_K(64)

#define DDRSGRF_BASE		0x10150000
#define DDRSGRF_SIZE		SIZE_K(64)

#define GRF_BASE		0x11000000
#define GRF_SIZE		SIZE_K(64)

#define UART2_BASE		0x11030000
#define UART2_SIZE		SIZE_K(64)

#define CRU_BASE		0x110e0000
#define CRU_SIZE		SIZE_K(64)

/* Internal SRAM */
#define ISRAM_BASE		0x10080000
#define ISRAM_SIZE		SIZE_K(8)

#elif defined(PLATFORM_FLAVOR_rk3399)

#define MMIO_BASE		0xF8000000

#define GIC_BASE		(MMIO_BASE + 0x06E00000)
#define GIC_SIZE		SIZE_M(2)
#define GICC_BASE		(MMIO_BASE + 0x07F00000)
#define GICD_BASE		GIC_BASE
#define GICR_BASE		(GIC_BASE + SIZE_M(1))

#define UART0_BASE		(MMIO_BASE + 0x07180000)
#define UART0_SIZE		SIZE_K(64)

#define UART1_BASE		(MMIO_BASE + 0x07190000)
#define UART1_SIZE		SIZE_K(64)

#define UART2_BASE		(MMIO_BASE + 0x071A0000)
#define UART2_SIZE		SIZE_K(64)

#define UART3_BASE		(MMIO_BASE + 0x071B0000)
#define UART3_SIZE		SIZE_K(64)

#define SGRF_BASE		(MMIO_BASE + 0x07330000)
#define SGRF_SIZE		SIZE_K(64)

#elif defined(PLATFORM_FLAVOR_px30)

#define GIC_BASE		0xff130000
#define GIC_SIZE		SIZE_K(64)
#define GICD_BASE		(GIC_BASE + 0x1000)
#define GICC_BASE		(GIC_BASE + 0x2000)

#define UART1_BASE		0xff158000
#define UART1_SIZE		SIZE_K(64)

#define UART2_BASE		0xff160000
#define UART2_SIZE		SIZE_K(64)

#define UART5_BASE		0xff178000
#define UART5_SIZE		SIZE_K(64)

#define FIREWALL_DDR_BASE	0xff534000
#define FIREWALL_DDR_SIZE	SIZE_K(16)

#elif defined(PLATFORM_FLAVOR_rk3506)

/*
 * RK3506B: Cortex-A7 x3, ARMv7-A, GICv2 (gic-400). DRAM at 0x0; the
 * U-Boot FIT loads tee.bin at CFG_TZDRAM_START (0x18000000 default,
 * 0x1000 with CFG_RK3506_TEE_HW_ISOLATE).
 */

#define GIC_BASE		0xff580000
#define GIC_SIZE		SIZE_K(64)
#define GICD_BASE		(GIC_BASE + 0x1000)
#define GICC_BASE		(GIC_BASE + 0x2000)

#define UART0_BASE		0xff0a0000
#define UART0_SIZE		SIZE_K(64)

/*
 * Internal SRAM (48 KB) at 0xfff80000.
 *
 * The BootROM parks the secondary cores in a WFE spin on a shared SRAM
 * mailbox at IRAM_BASE (flag word +0x04 polled for 0xdeadbeaf, entry
 * word +0x08). To release a core, write the pen PA to the entry word,
 * the magic to the flag word, then SEV. The pen and the per-core gate
 * slots sit clear of the mailbox stub (IRAM_BASE..+0x0f) and of each
 * other. See psci_rk3506.c / pen_rk3506.S.
 */
#define IRAM_BASE		0xfff80000
#define IRAM_SIZE		SIZE_K(48)
/* BootROM mailbox words (BootROM-defined; do not relocate). */
#define RK3506_BROM_FLAG_PA	(IRAM_BASE + 0x04)	/* poll word */
#define RK3506_BROM_ENTRY_PA	(IRAM_BASE + 0x08)	/* entry PA  */
#define RK3506_BROM_MAGIC	0xdeadbeafu		/* release   */
#define RK3506_PEN_PA		(IRAM_BASE + 0x0800)
#define RK3506_SLOTS_PA		(IRAM_BASE + 0x0d00)

/*
 * System firewall / SGRF "slave-security" block at 0xff210000.
 * Programmed by platform_secure_init() with the rk322x SLAVE_ALL_NS
 * masked-write idiom to make peripherals (notably the UART0 console)
 * non-secure-accessible; without it the NS world's first UART0 access
 * external-aborts.
 */
#define FIREWALL_SYS_BASE	0xff210000
#define FIREWALL_SYS_SIZE	SIZE_K(64)

/*
 * DDR firewall (FW_DDR) at 0xff5f0000. Register layout:
 *   +0x00.. : region-map regs (128 KB granule, 0x7fff field encoding)
 *   +0x20.. : per-master access regs (0xffffffff = NS-allow)
 *   +0x30   : access reg (low byte significant)
 *   +0x40   : control/enable reg, bit N = region N enable
 * Field encodings follow the BSD-2 OP-TEE px30/rk3588 ports. See
 * platform_rk3506.c.
 */
#define FIREWALL_DDR_BASE	0xff5f0000
#define FIREWALL_DDR_SIZE	SIZE_K(64)

#elif defined(PLATFORM_FLAVOR_rk3588)

#define GIC_BASE		0xfe600000
#define GIC_SIZE		SIZE_K(64)
#define GICC_BASE		0
#define GICD_BASE		GIC_BASE
#define GICR_BASE		(GIC_BASE + 0x80000)

#define UART0_BASE		0xfd890000
#define UART0_SIZE		SIZE_K(64)

#define UART1_BASE		0xfeb40000
#define UART1_SIZE		SIZE_K(64)

#define UART2_BASE		0xfeb50000
#define UART2_SIZE		SIZE_K(64)

#define UART3_BASE		0xfeb60000
#define UART3_SIZE		SIZE_K(64)

#define FIREWALL_DDR_BASE	0xfe030000
#define FIREWALL_DDR_SIZE	SIZE_K(32)

#define FIREWALL_DSU_BASE	0xfe010000
#define FIREWALL_DSU_SIZE	SIZE_K(32)

#define TRNG_S_BASE		0xfe398000
#define TRNG_S_SIZE		SIZE_K(32)

#define OTP_S_BASE		0xfe3a0000
#define OTP_S_SIZE		SIZE_K(64)

#define ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX	0x8
#define ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE	0x1
#define ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE	0x00ff
#define ROCKCHIP_OTP_SECURE_BOOT_STATUS_RSA4096	0x3000
#define ROCKCHIP_OTP_HUK_INDEX			0x104
#define ROCKCHIP_OTP_HUK_SIZE			0x4
#define ROCKCHIP_OTP_RSA_HASH_INDEX		0x270
#define ROCKCHIP_OTP_RSA_HASH_SIZE		0x8

#elif defined(PLATFORM_FLAVOR_rk3576)

#define GIC_BASE		0x2a700000
#define GIC_SIZE		SIZE_K(64)
#define GICD_BASE		(GIC_BASE + 0x1000)
#define GICC_BASE		(GIC_BASE + 0x2000)

#define UART0_BASE		0x2ad40000
#define UART0_SIZE		SIZE_K(64)

#define SYS_SGRF_BASE		0x26004000
#define SYS_SGRF_SIZE		SIZE_K(4)

#define SYS_SGRF_FW_BASE	0x26005000
#define SYS_SGRF_FW_SIZE	SIZE_K(4)

#define PMU0SGRF_BASE		0x26000000
#define PMU0SGRF_SIZE		SIZE_K(4)

#define PMU1SGRF_BASE		0x26002000
#define PMU1SGRF_SIZE		SIZE_K(4)

#define PMU1SGRF_FW_BASE	0x26003000
#define PMU1SGRF_FW_SIZE	SIZE_K(4)

#elif defined(PLATFORM_FLAVOR_rv1106)

/* GIC-400 (GICv2) */
#define GIC_BASE		0xff1f0000
#define GIC_SIZE		SIZE_K(64)
#define GICD_BASE		(GIC_BASE + 0x1000)
#define GICC_BASE		(GIC_BASE + 0x2000)

/* UART2 debug console */
#define UART2_BASE		0xff4c0000
#define UART2_SIZE		SIZE_K(64)

/*
 * System-firewall (SGRF) bases. PERI_SGRF gates the peripherals the NS world
 * owns (including the UART2 console); CORE_SGRF gates the core/HPMCU domain.
 * A 4 KiB page each covers the register offsets used here.
 */
#define PERI_SGRF_BASE		0xff070000
#define PERI_SGRF_SIZE		SIZE_K(4)
#define CORE_SGRF_BASE		0xff076000
#define CORE_SGRF_SIZE		SIZE_K(4)

/*
 * DDR-firewall base. The FW_DDR region (RGN) and enable (CON) layout is the
 * same IP as the upstream plat-rk3588 FW_DDR block; see platform_rv1106.c.
 */
#define FW_DDR_BASE		0xff900000
#define FW_DDR_SIZE		SIZE_K(64)

#elif defined(PLATFORM_FLAVOR_rk3568)

#define GIC_BASE		0xfd400000
#define GIC_SIZE		SIZE_K(64)
#define GICC_BASE		0
#define GICD_BASE		GIC_BASE
#define GICR_BASE		(GIC_BASE + 0x60000)

#define UART0_BASE		0xfdd50000
#define UART0_SIZE		SIZE_K(64)

#define UART2_BASE		0xfe660000
#define UART2_SIZE		SIZE_K(64)

#define FIREWALL_DDR_BASE	0xfe200000
#define FIREWALL_DDR_SIZE	SIZE_K(4)

#define SCRU_BASE		0xfdd10000
#define SCRU_SIZE		SIZE_K(4)

#define TRNG_S_BASE		0xfe370000
#define TRNG_S_SIZE		SIZE_K(64)

#define CRU_BASE		0xfdd20000
#define CRU_SIZE		SIZE_K(4)

#define SGRF_BASE		0xfdd18000
#define SGRF_SIZE		SIZE_K(4)

#define OTP_S_BASE		0xfe3a0000
#define OTP_S_SIZE		SIZE_K(16)

/*
 * Halfword address/count in the secure OTP region (0x000-0x1bf). The
 * area starting at 0x100 (byte 0x200) is well clear of the cells used
 * by the boot chain (secure-boot enable flag at byte 0x80, RSA pubkey
 * hash at bytes 0x90-0xaf, anti-rollback counter at bytes 0xe0-0xe7)
 * and lies in the range the vendor secure OTP driver allows writing.
 *
 * A provisioning marker halfword is burned last, after the key has been
 * written and verified, so an interrupted first-boot burn is detectable
 * (the marker stays blank) and never mistaken for a valid short key.
 */
#define ROCKCHIP_OTP_HUK_ADDR		0x100
#define ROCKCHIP_OTP_HUK_SIZE		0x8
#define ROCKCHIP_OTP_HUK_MARKER_ADDR	0x108
#define ROCKCHIP_OTP_HUK_MARKER		0x4b48

#else
#error "Unknown platform flavor"
#endif

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		5
#endif

#endif
