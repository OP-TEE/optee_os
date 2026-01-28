# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026, Altera Corporation.
#

PLATFORM_FLAVOR ?= agilex5
include core/arch/arm/plat-altera/flavors/$(PLATFORM_FLAVOR).mk

$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)

# Memory layout
# Valid DRAM: 0x80000000-0xEFFFFFFF (1792MB with inline ECC)
# Service Layer: 0x80000000-0x81FFFFFF (32MB, SDM/mailbox)
# Linux kernel loads: 0x80080000-0x825FFFFF (~37MB)
# Place OP-TEE after kernel to avoid overlap: 0x83000000-0x84FFFFFF (32MB)
CFG_TZDRAM_START ?= 0x83000000
CFG_TZDRAM_SIZE ?= 0x02000000

$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_CORE_DYN_SHM,y)

$(call force,CFG_8250_UART,y)
CFG_8250_UART_BASE ?= 0x10C02000
CFG_CONSOLE_UART ?= 0

$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_STATS,y)

CFG_CRYPTO_WITH_CE ?= n
CFG_WITH_SOFTWARE_PRNG ?= y

CFG_TEE_CORE_LOG_LEVEL ?= 2

include core/arch/arm/cpu/cortex-armv8-0.mk
