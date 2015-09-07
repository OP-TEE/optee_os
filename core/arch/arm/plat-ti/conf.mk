include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CFG_ARM32_core ?= y
CFG_MMU_V7_TTB ?= y

core-platform-cppflags	+= -I$(arch-dir)/include

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
core-platform-subdirs += $(arch-dir)/sm

libutil_with_isoc := y
libtomcrypt_with_optimize_size := y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_8250_UART ?= y
CFG_HWSUPP_MEM_PERM_PXN := y
CFG_WITH_STACK_CANARIES := y
CFG_PM_STUBS := y
CFG_GENERIC_BOOT := y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_NO_TA_HASH_SIGN ?= y
CFG_WITH_SOFTWARE_PRNG ?= y

include mk/config.mk
