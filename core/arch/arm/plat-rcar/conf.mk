PLATFORM_FLAVOR ?= salvator_h3

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)

ifeq ($(PLATFORM_FLAVOR),salvator_h3)
$(call force,CFG_TEE_CORE_NB_CORE,8)
endif
ifeq ($(PLATFORM_FLAVOR),salvator_m3)
$(call force,CFG_TEE_CORE_NB_CORE,4)
endif

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
supported-ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_WITH_STACK_CANARIES ?= y
