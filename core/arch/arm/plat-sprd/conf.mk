PLATFORM_FLAVOR ?= sc9860

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
endif

$(call force,CFG_GIC,y)
$(call force,CFG_SPRD_UART,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

# Overrides default in mk/config.mk with 128 kB
CFG_CORE_HEAP_SIZE ?= 131072
