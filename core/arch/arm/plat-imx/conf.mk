include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_COMPILE	?= arm-linux-gnueabihf-
COMPILER	?= gcc

CFG_ARM32_core ?= y
CFG_MMU_V7_TTB ?= y

core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
core-platform-subdirs += $(arch-dir)/sm

libutil_with_isoc := y
CFG_GENERIC_BOOT ?= y
CFG_IMX_UART ?= y
CFG_MMU_V7_TTB ?= y
CFG_NO_TA_HASH_SIGN ?= y
CFG_PM_STUBS ?= y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_WITH_SOFTWARE_PRNG ?= y
CFG_WITH_STACK_CANARIES := y

include mk/config.mk

core-platform-cppflags += -D_USE_SLAPORT_LIB

core-platform-cppflags += -DCFG_NO_TA_HASH_SIGN
CFG_GIC := y
