# HOYA architecture configuration

include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)

$(call force,CFG_QCOM_RAMBLUR_PIMEM_V3,y)
CFG_QCOM_RAMBLUR_TA_WINDOW_ID ?= 2

$(call force,CFG_QCOM_PRNG,y)

CFG_TZDRAM_START ?= 0x1c300000
CFG_TEE_RAM_VA_SIZE ?= 0x200000
CFG_TA_RAM_VA_SIZE ?= 0x1c00000
CFG_TZDRAM_SIZE ?= (CFG_TEE_RAM_VA_SIZE + CFG_TA_RAM_VA_SIZE)
CFG_NUM_THREADS ?= 8
