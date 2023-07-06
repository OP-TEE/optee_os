include core/arch/arm/cpu/cortex-armv8-0.mk

CFG_TEE_CORE_NB_CORE ?= 128
CFG_NUM_THREADS ?= 96
CFG_CRYPTO_WITH_CE ?= y

CFG_WITH_PAGER ?= n
CFG_WITH_SOFTWARE_PRNG ?= y
CFG_WITH_STATS ?= y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_HISILICON_CRYPTO_DRIVER ?= y

$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,48)
$(call force,CFG_LPC_UART,y)

CFG_TEE_CORE_LOG_LEVEL ?= 4

CFG_CORE_HEAP_SIZE ?= 0x008000000
CFG_CORE_ARM64_PA_BITS ?= 40
CFG_TEE_RAM_VA_SIZE ?= 0x009000000
CFG_TZDRAM_START ?=    0x20C0000000
CFG_TZDRAM_SIZE ?=     0x32000000
CFG_SHMEM_START ?=     0x50000000
CFG_SHMEM_SIZE ?=      0x04000000
