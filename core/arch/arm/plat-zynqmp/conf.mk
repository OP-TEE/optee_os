PLATFORM_FLAVOR ?= zcu102

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_CDNS_UART,y)
$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as ATF does not provide a
#    DTB to OP-TEE. Hardware RNG is also not currently supported.
# 2. OP-TEE does not boot with enabled CFG_CORE_ASLR.
$(call force,CFG_CORE_ASLR,n)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
endif

CFG_TZDRAM_START ?= 0x60000000
CFG_TZDRAM_SIZE  ?= 0x10000000
CFG_SHMEM_START  ?= 0x70000000
CFG_SHMEM_SIZE   ?= 0x10000000

CFG_WITH_STATS ?= y
CFG_CRYPTO_WITH_CE ?= y
