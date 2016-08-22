PLATFORM_FLAVOR ?= h3

# 32-bit flags
arm32-platform-cpuarch	:= cortex-a57
arm32-platform-cflags	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
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
