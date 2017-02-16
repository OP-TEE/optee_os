PLATFORM_FLAVOR ?= mx6ulevk

ifeq ($(PLATFORM_FLAVOR),mx6ulevk)
arm32-platform-cpuarch		:= cortex-a7
endif
ifeq ($(PLATFORM_FLAVOR),$(filter $(PLATFORM_FLAVOR),mx6qsabrelite mx6qsabresd mx6dlsabresd))
arm32-platform-cpuarch		:= cortex-a9
endif
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_ARM32_core,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
ifeq ($(PLATFORM_FLAVOR),mx6ulevk)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
endif
ifeq ($(PLATFORM_FLAVOR),$(filter $(PLATFORM_FLAVOR),mx6qsabrelite mx6qsabresd mx6dlsabresd))
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)

CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
endif

ta-targets = ta_arm32

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
