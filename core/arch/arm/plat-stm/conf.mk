include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CFG_ARM32_core ?= y

core-platform-cppflags	+= -I$(arch-dir)/include

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
core-platform-subdirs += $(arch-dir)/sm

libutil_with_isoc ?= y
libtomcrypt_with_optimize_size ?= y
CFG_SECURE_TIME_SOURCE_REE ?= y
CFG_PL310 ?= y
CFG_CACHE_API ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_PM_STUBS ?= y
CFG_GENERIC_BOOT ?= y
CFG_WITH_SOFTWARE_PRNG ?= n
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STATS ?= y
CFG_MMU_V7_TTB ?= y
CFG_PL310_LOCKED ?= n
CFG_TEE_GDB_BOOT ?= y
CFG_BOOT_SYNC_CPU ?= y

include mk/config.mk
include $(platform-dir)/system_config.mk
