PLATFORM_FLAVOR ?= sc9860

# 32-bit flags
arm32-platform-cpuarch		:= cortex-a15
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mfpu=neon

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_SPRD_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)

CFG_WITH_STACK_CANARIES ?= y
# Overrides default in mk/config.mk with 128 kB
CFG_CORE_HEAP_SIZE ?= 131072
