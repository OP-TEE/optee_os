include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,16)
CFG_NUM_THREADS ?= 16
CFG_CRYPTO_WITH_CE ?= y
CFG_WITH_SOFTWARE_PRNG ?= n
# Overrides default in mk/config.mk with 96 kB
CFG_CORE_HEAP_SIZE ?= 98304

$(call force,CFG_HI16XX_UART,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
ifneq ($(CFG_WITH_SOFTWARE_PRNG),y)
$(call force,CFG_HI16XX_RNG,y)
endif
$(call force,CFG_WITH_LPAE,y)

ifeq ($(CFG_ARM64_core),y)
CFG_CORE_TZSRAM_EMUL_SIZE ?= 655360
else
$(call force,CFG_ARM32_core,y)
CFG_CORE_TZSRAM_EMUL_SIZE ?= 524288
endif

# 20MB-384kB of secure RAM
ifeq ($(CFG_WITH_PAGER),y)
CFG_TEE_RAM_VA_SIZE ?= 0x00400000
else
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
endif
CFG_TZDRAM_START ?= 0x50400000
CFG_TZDRAM_SIZE ?= 0x013a00000
CFG_SHMEM_START ?= 0x50000000
CFG_SHMEM_SIZE ?= 0x00400000

