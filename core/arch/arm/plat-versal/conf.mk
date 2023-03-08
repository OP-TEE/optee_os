PLATFORM_FLAVOR ?= generic

include core/arch/arm/cpu/cortex-armv8-0.mk

CFG_MMAP_REGIONS ?= 24

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_PL011,y)
$(call force,CFG_GIC,y)

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as TF-a does not provide a
#    DTB to OP-TEE. Hardware RNG is also not currently supported.
# 2. Xilinx's bootgen can't find the OP-TEE entry point from the TEE.elf file
#    used to generate boot.bin. Enabling ASLR requires an update to TF-A.
$(call force,CFG_CORE_ASLR,n)

CFG_CRYPTO_WITH_CE ?= y
CFG_CORE_DYN_SHM   ?= y
CFG_WITH_STATS     ?= y
CFG_ARM64_core     ?= y

CFG_TZDRAM_START   ?= 0x60000000
CFG_TZDRAM_SIZE    ?= 0x10000000
CFG_SHMEM_START    ?= 0x70000000
CFG_SHMEM_SIZE     ?= 0x10000000

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_CORE_ARM64_PA_BITS,43)
else
$(call force,CFG_ARM32_core,y)
endif

# GPIO
CFG_VERSAL_GPIO ?= y

# Debug information
CFG_VERSAL_TRACE_MBOX ?= n
CFG_VERSAL_TRACE_PLM ?= n

$(call force, CFG_VERSAL_MBOX,y)

# MBOX configuration
CFG_VERSAL_MBOX_IPI_ID ?= 3

$(call force, CFG_VERSAL_RNG_DRV,y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)

# TRNG configuration
CFG_VERSAL_TRNG_SEED_LIFE ?= 3
CFG_VERSAL_TRNG_DF_MUL ?= 2

# eFuse and BBRAM driver
$(call force, CFG_VERSAL_NVM,y)

# Crypto driver
CFG_VERSAL_CRYPTO_DRIVER ?= y
ifeq ($(CFG_VERSAL_CRYPTO_DRIVER),y)
# Disable Fault Mitigation: triggers false positives due to
# the driver's software fallback operations - need further work
CFG_FAULT_MITIGATION ?= n
endif

# SHA3-384 crypto engine
CFG_VERSAL_SHA3_384 ?= y

# PM driver
CFG_VERSAL_PM ?= y

# Physical Unclonable Function
CFG_VERSAL_PUF ?= y

# Enable Hardware Unique Key driver
CFG_VERSAL_HUK ?= y
# AES-GCM supported key sources for HUK:
#     6  : eFUSE USR 0
#     7  : eFuse USR 1
#    11  : PUF KEK
#    12  : AES User Key 0 (devel)
CFG_VERSAL_HUK_KEY ?= 12
ifneq ($(CFG_VERSAL_HUK_KEY),$(filter 6 7 11 12,$(firstword $(CFG_VERSAL_HUK_KEY))))
$(error Invalid value: CFG_VERSAL_HUK_KEY=$(CFG_VERSAL_HUK_KEY))
endif

CFG_CORE_HEAP_SIZE ?= 262144
