include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_COMPILE	?= arm-linux-gnueabihf-
COMPILER	?= gcc

CFG_ARM32_core ?= y
CFG_NUM_THREADS ?= 4

core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
core-platform-subdirs += $(arch-dir)/sm

libutil_with_isoc := y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_WITH_SEC_MON := y
CFG_WITH_STACK_CANARIES := y
CFG_SUNXI_UART ?= y

include mk/config.mk

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= 1
core-platform-cppflags += \
	-DCFG_TEE_CORE_EMBED_INTERNAL_TESTS=$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS)

core-platform-cppflags += -DTEE_USE_DLMALLOC
core-platform-cppflags += -D_USE_SLAPORT_LIB

core-platform-cppflags += -DCFG_NO_TA_HASH_SIGN
CFG_GIC := y
