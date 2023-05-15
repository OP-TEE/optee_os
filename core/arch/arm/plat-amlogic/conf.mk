PLATFORM_FLAVOR ?= axg

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,4)

CFG_TZDRAM_START ?= 0x05300000
CFG_TZDRAM_SIZE ?= 0x00c00000
CFG_SHMEM_START ?= 0x05000000
CFG_SHMEM_SIZE ?= 0x00100000

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_AMLOGIC_UART,y)

$(call force,CFG_WITH_PAGER,n)
$(call force,CFG_ARM64_core,y)
