# Wildcat architecture configuration

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_ARM_GICV4,y)

# DARE-TZ secure memory regions
CFG_TZDRAM_START ?= 0xBC280000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
CFG_TA_RAM_VA_SIZE ?= 0x07B80000
CFG_TZDRAM_SIZE ?= (CFG_TEE_RAM_VA_SIZE + CFG_TA_RAM_VA_SIZE)
CFG_NUM_THREADS ?= 8
