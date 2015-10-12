include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_PREFIX	?= arm-linux-gnueabihf
CROSS_COMPILE	?= $(CROSS_PREFIX)-
include mk/gcc.mk

PLATFORM_FLAVOR ?= ls1021atwr

CFG_ARM32_core ?= y
CFG_MMU_V7_TTB ?= y

core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)

core-platform-subdirs += $(arch-dir)/sm

libutil_with_isoc := y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_WITH_STACK_CANARIES := y
CFG_16550_UART ?= y
CFG_GENERIC_BOOT ?= y
CFG_PM_STUBS ?= y
CFG_BOOT_SYNC_CPU ?= y

include mk/config.mk

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= n
