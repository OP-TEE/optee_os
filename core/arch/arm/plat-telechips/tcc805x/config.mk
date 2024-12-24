CFG_PL011 ?= y
CFG_TCC_OMC ?= y
CFG_ARM_SMCCC_TRNG ?= y

$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,35)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_NUM_THREADS,4)

CFG_TZDRAM_START	?= 0x2E000000
CFG_TZDRAM_SIZE		?= 0x02000000

include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_ARM64_core,y)

TCMKTOOL_IMGNAME ?= A72-OPTEE
