# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020-2026, NVIDIA CORPORATION & AFFILIATES
#

include core/arch/arm/cpu/cortex-armv8-0.mk

tegra-platform-flavors := t234 t264

ifeq (,$(filter $(PLATFORM_FLAVOR),$(tegra-platform-flavors)))
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)" \
    (supported: $(tegra-platform-flavors)))
endif

# TZDRAM and SHMEM addresses and sizes
CFG_TZDRAM_START ?= 0x80000000

# Use dynamic shared memory and disable static shared memory because
# the NS shared memory address and size are calculated dynamically
$(call force,CFG_CORE_DYN_SHM,y)
$(call force,CFG_CORE_RESERVED_SHM,n)

# The NS memory range will be calculated automatically.
$(call force,CFG_AUTO_MAX_PA_BITS,y)

# Enable ARM64 core
$(call force,CFG_ARM64_core,y)

# Default number of threads is the number of CPU cores
CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)

# Default heap size for Core, 128 kB
CFG_CORE_HEAP_SIZE ?= 131072

# Default size for reserved virtual memory space, 32 MB
CFG_RESERVED_VASPACE_SIZE ?= (1024 * 1024 * 32)

# Increase the mmap region to accommodate more
# device mappings in the global static map
CFG_MMAP_REGIONS ?= 24

# Makes sure everything built is 64-bit, even TA targets.
supported-ta-targets = ta_arm64

# Enables large physical address extension, necessary if ARM64 core is initialized.
$(call force,CFG_WITH_LPAE,y)

$(call force,CFG_LPAE_ADDR_SPACE_BITS,38)
$(call force,CFG_WITH_PAGER,n)

# Lets platform interact with ATF
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Initialize kernel time source
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

CFG_DTB_MAX_SIZE ?= 0x10000
$(call force,CFG_DT,y)

# CFG_RPMB_FS / CFG_RPMB_KEY_HAS_PROVISIONED are opted into per-platform conf
# not forced here so a platform can enable them (default is n).
$(call force,CFG_RPMB_WRITE_KEY,n)
$(call force,CFG_RPMB_TESTKEY,n)

# Enable PKCS11 tests in xtest
$(call force,CFG_PKCS11_TA,y)

# Set the default log level to INFO
$(call force,CFG_TEE_CORE_LOG_LEVEL,2)

# Trusted OS implementation version
# Overriding TEE_IMPL_VERSION for consistency in version reporting
TEE_IMPL_VERSION = $(CFG_OPTEE_REVISION_MAJOR).$(CFG_OPTEE_REVISION_MINOR)

$(call force,CFG_CORE_PHYS_RELOCATABLE,y)

CFG_TEE_RAM_VA_SIZE ?= 0x400000

ifeq ($(PLATFORM_FLAVOR),t234)
CFG_TZDRAM_SIZE  ?= 0x03f80000

# T234 has 3 clusters and 4 cores per cluster
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
# Secondary CPU cores. t234 platform contains 12 CPU cores
$(call force,CFG_TEE_CORE_NB_CORE,12)

$(call force,CFG_MAP_EXT_DT_SECURE,y)

# Enable Early TA support
$(call force,CFG_EARLY_TA,y)
$(call force,CFG_EMBEDDED_TS,y)

# Enable Pointer Authentication for core (S-EL1)
$(call force,CFG_CORE_PAUTH,y)

# Disable Pointer Authentication for TA (S-EL0)
$(call force,CFG_TA_PAUTH,n)

# Leverage relocatable optee feature while not enable EL2 SPMC
$(call force,CFG_CORE_SEL2_SPMC,n)

# Enable tegra combined UART driver
$(call force,CFG_TEGRA_TCU,y)

$(call force,CFG_CORE_ASLR,y)
endif

ifeq ($(PLATFORM_FLAVOR),t264)
CFG_TZDRAM_SIZE  ?= 0x02000000

# Secondary CPU cores. t264 platform contains 14 CPU cores
$(call force,CFG_TEE_CORE_NB_CORE,14)

CFG_TEE_DYN_VASPACE_SIZE ?= (2 * 1024 * 1024)

$(call force,CFG_MAP_EXT_DT_SECURE,y)

# Enable Early TA support
$(call force,CFG_EARLY_TA,y)
$(call force,CFG_EMBEDDED_TS,y)

$(call force,CFG_ARM64_core,y)
$(call force,CFG_CORE_FFA,y)
$(call force,CFG_FFA_CONSOLE,y)
$(call force,CFG_CORE_SEL2_SPMC,y)
$(call force,CFG_WITH_STACK_CANARIES,y)
$(call force,CFG_TEGRA_UTC,y)

$(call force,CFG_CORE_ASLR,y)

CFG_STACK_TMP_EXTRA ?= 8192
endif
