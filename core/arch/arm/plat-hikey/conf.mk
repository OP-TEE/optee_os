# 32-bit flags
arm32-platform-cpuarch		:= cortex-a53
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_PL011,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_NUM_THREADS ?= 8
CFG_CRYPTO_WITH_CE ?= y
CFG_WITH_STACK_CANARIES ?= y

CFG_PL061 ?= y
CFG_PL022 ?= y
CFG_SPI ?= y

ifeq ($(CFG_SPI_TEST),y)
$(call force,CFG_SPI,y)
endif

ifeq ($(CFG_SPI),y)
$(call force,CFG_PL061,y)
$(call force,CFG_PL022,y)
endif

ifeq ($(CFG_PL061),y)
core-platform-cppflags		+= -DPLAT_PL061_MAX_GPIOS=160
endif
