# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025-2026, Renesas Electronics Corporation.
#

PLATFORM_FLAVOR ?= X5H
include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
# Disable core ASLR until there is RNG driver.
$(call force,CFG_CORE_ASLR,n)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_DYN_CONFIG,n)

ifeq ($(PLATFORM_FLAVOR), X5H)
$(call force,CFG_RCAR_GEN5, y)
endif

CFG_OPTEE_VENDOR_REVISION_MAJOR = 1
CFG_OPTEE_VENDOR_REVISION_MINOR = 0
CFG_OPTEE_VENDOR_REVISION_EXTRA = 0
CFG_OPTEE_VENDOR_REVISION_VER = $(CFG_OPTEE_VENDOR_REVISION_MAJOR).$(CFG_OPTEE_VENDOR_REVISION_MINOR).$(CFG_OPTEE_VENDOR_REVISION_EXTRA)
CFG_OPTEE_VENDOR_REVISION = +renesas$(CFG_OPTEE_VENDOR_REVISION_VER)

# Trusted OS implementation version
# Override TEE_IMPL_VERSION and include Renesas patch parity level
TEE_IMPL_VERSION = $(shell git describe --always --dirty=-dev 2>/dev/null || \
		     echo Unknown_$(CFG_OPTEE_REVISION_MAJOR).$(CFG_OPTEE_REVISION_MINOR))$(CFG_OPTEE_REVISION_EXTRA)$(CFG_OPTEE_VENDOR_REVISION)

ifneq ($(CFG_CORE_HAFNIUM_INTC),y)
$(call force,CFG_GIC,y)
CFG_ARM_GICV3 ?= y
endif
CFG_CRYPTO_WITH_CE ?= n
CFG_TZDRAM_START ?= 0x8C400000
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
supported-ta-targets = ta_arm64
CFG_DT ?= n
CFG_WITH_SOFTWARE_PRNG ?= y

ifeq ($(CFG_RCAR_GEN5),y)
$(call force,CFG_CORE_CLUSTER_SHIFT,2) # 4 cores per cluster
$(call force,CFG_TEE_CORE_NB_CORE,32)
CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)
CFG_MMAP_REGIONS ?= 21
endif

# For virtualization
ifeq ($(CFG_NS_VIRTUALIZATION),y)
CFG_VIRT_GUEST_COUNT ?= 3
CFG_CORE_RESERVED_SHM ?= n
endif
