PLATFORM_FLAVOR ?= h3

include core/arch/arm/cpu/cortex-armv8-0.mk

# 32-bit flags
arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,y)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

ifeq ($(CFG_ARM32_core),y)
ta-targets = ta_arm32
endif

CFG_WITH_STACK_CANARIES ?= y
