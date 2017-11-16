PLATFORM_FLAVOR ?= armada7k8k

# 32-bit flags
core_arm32-platform-aflags	+= -mfpu=neon

ifeq ($(PLATFORM_FLAVOR),armada7k8k)
include core/arch/arm/cpu/cortex-armv8-0.mk
platform-debugger-arm := 1
$(call force,CFG_8250_UART,y)
endif

ifeq ($(PLATFORM_FLAVOR),armada3700)
include core/arch/arm/cpu/cortex-armv8-0.mk
platform-debugger-arm := 1
$(call force,CFG_MVEBU_UART,y)
$(call force,CFG_ARM_GICV3,y)
endif

ifeq ($(platform-debugger-arm),1)
# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2
endif

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
