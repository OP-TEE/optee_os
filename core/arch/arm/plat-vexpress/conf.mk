include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_PL011,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
$(call force,CFG_MMU_V7_TTB,y)
endif

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
else
core-platform-subdirs += $(arch-dir)/sm
endif

libtomcrypt_with_optimize_size ?= y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_TEE_FS_KEY_MANAGER_TEST ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y

ifeq ($(PLATFORM_FLAVOR),juno)
CFG_CRYPTO_AES_ARM64_CE ?= $(CFG_ARM64_core)
CFG_CRYPTO_SHA1_ARM32_CE ?= $(CFG_ARM32_core)
CFG_CRYPTO_SHA1_ARM64_CE ?= $(CFG_ARM64_core)
CFG_CRYPTO_SHA256_ARM32_CE ?= $(CFG_ARM32_core)
CFG_CRYPTO_SHA256_ARM64_CE ?= $(CFG_ARM64_core)
endif

# SE API is only supported by QEMU Virt platform
ifeq ($(PLATFORM_FLAVOR),qemu_virt)
CFG_SE_API ?= y
CFG_SE_API_SELF_TEST ?= y
CFG_PCSC_PASSTHRU_READER_DRV ?= y
endif

include mk/config.mk
