include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

ifeq ($(CFG_ARM64_core),y)
CFG_WITH_LPAE := y
else
CFG_ARM32_core ?= y
CFG_MMU_V7_TTB ?= y
endif

core-platform-cppflags	+= -I$(arch-dir)/include

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
ifeq ($(platform-flavor-armv8),1)
CFG_WITH_ARM_TRUSTED_FW := y
else
core-platform-subdirs += $(arch-dir)/sm
endif

libutil_with_isoc := y
libtomcrypt_with_optimize_size := y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_PL011 := y
CFG_GIC := y
CFG_HWSUPP_MEM_PERM_PXN := y
CFG_WITH_STACK_CANARIES := y
CFG_PM_STUBS := y
CFG_GENERIC_BOOT := y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_TEE_FS_KEY_MANAGER_TEST := y
CFG_NO_TA_HASH_SIGN ?= y

ifeq ($(PLATFORM_FLAVOR),juno)
CFG_CRYPTO_SHA256_ARM32_CE ?= $(CFG_ARM32_core)
CFG_CRYPTO_SHA1_ARM32_CE ?= $(CFG_ARM32_core)
endif

# SE API is only supported by QEMU Virt platform
ifeq ($(PLATFORM_FLAVOR),qemu_virt)
CFG_SE_API := y
CFG_SE_API_SELF_TEST := y
CFG_PCSC_PASSTHRU_READER_DRV := y
endif

ifeq ($(CFG_CRYPTO_SHA256_ARM32_CE),y)
CFG_WITH_VFP := y
endif
ifeq ($(CFG_CRYPTO_SHA1_ARM32_CE),y)
CFG_WITH_VFP := y
endif

include mk/config.mk
