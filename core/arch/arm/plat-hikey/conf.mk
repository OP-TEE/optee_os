include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_COMPILE	?= arm-linux-gnueabihf-
COMPILER	?= gcc

ifeq ($(CFG_ARM64_core),y)
CFG_WITH_LPAE := y
else
CFG_ARM32_core ?= y
CFG_MMU_V7_TTB ?= y
endif

core-platform-cppflags	+= -I$(arch-dir)/include

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee) $(platform-dir)

libutil_with_isoc := y
libtomcrypt_with_optimize_size := y

CFG_WITH_ARM_TRUSTED_FW := y
CFG_SECURE_TIME_SOURCE_CNTPCT ?= y
CFG_PL011 ?= y
CFG_HWSUPP_MEM_PERM_PXN ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_NO_TA_HASH_SIGN ?= y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= n
CFG_GENERIC_BOOT ?= y
CFG_PM_STUBS ?= y
CFG_CRYPTO_SHA256_ARM32_CE ?= $(CFG_ARM32_core)
CFG_CRYPTO_SHA1_ARM32_CE ?= $(CFG_ARM32_core)
CFG_CRYPTO_AES_ARM64_CE ?= $(CFG_ARM64_core)

ifeq ($(CFG_CRYPTO_SHA256_ARM32_CE),y)
CFG_WITH_VFP := y
endif
ifeq ($(CFG_CRYPTO_SHA1_ARM32_CE),y)
CFG_WITH_VFP := y
endif
ifeq ($(CFG_CRYPTO_AES_ARM64_CE),y)
CFG_WITH_VFP := y
endif

include mk/config.mk
