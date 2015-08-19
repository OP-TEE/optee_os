PLATFORM_FLAVOR ?= dra7xx

CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
CFG_WITH_SOFTWARE_PRNG ?= n

$(call force,CFG_SM_PLATFORM_HANDLER,y)
$(call force,CFG_8250_UART,y)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
ifneq ($(CFG_WITH_SOFTWARE_PRNG),y)
$(call force,CFG_DRA7_RNG,y)
endif

# 32-bit flags
arm32-platform-cpuarch		:= cortex-a15
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

ta-targets = ta_arm32
