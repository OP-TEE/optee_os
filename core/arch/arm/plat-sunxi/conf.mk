include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CFG_ARM32_core ?= y
CFG_NUM_THREADS ?= 4

core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
core-platform-subdirs += $(arch-dir)/sm

libutil_with_isoc := y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_WITH_STACK_CANARIES := y
CFG_SUNXI_UART ?= y
CFG_MMU_V7_TTB ?= y
CFG_PM_STUBS ?= y

include mk/config.mk

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y

core-platform-cppflags += -DTEE_USE_DLMALLOC
core-platform-cppflags += -D_USE_SLAPORT_LIB

CFG_GIC := y
