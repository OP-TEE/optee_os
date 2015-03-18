include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_COMPILE	?= arm-linux-gnueabihf-
COMPILER	?= gcc

ifeq ($(CFG_ARM64_core),y)
CFG_WITH_LPAE := y
else
CFG_ARM32_core ?= y
endif

ifeq ($(CFG_ARM64_core),y)
core-platform-cppflags += $(arm64-platform-cppflags)
core-platform-cflags += $(arm64-platform-cflags)
core-platform-aflags += $(arm64-platform-aflags)
else
core-platform-cppflags += $(arm32-platform-cppflags)
core-platform-cflags += $(arm32-platform-cflags)
core-platform-aflags += $(arm32-platform-aflags)
endif

core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-cppflags	+= -DNUM_THREADS=2

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
ifeq ($(platform-flavor-armv8),1)
CFG_WITH_ARM_TRUSTED_FW := y
else
core-platform-subdirs += $(arch-dir)/sm
CFG_WITH_SEC_MON := y
endif

CFG_PM_DEBUG ?= n

libutil_with_isoc := y
libtomcrypt_with_optimize_size := y
WITH_SECURE_TIME_SOURCE_CNTPCT := y
WITH_UART_DRV := y
WITH_GIC_DRV := y
CFG_HWSUPP_MEM_PERM_PXN := y
CFG_WITH_STACK_CANARIES := y

ifeq ($(PLATFORM_FLAVOR),juno)
CFG_CRYPTO_SHA256_ARM32_CE ?= y
CFG_CRYPTO_SHA1_ARM32_CE ?= y
endif

# SE API is only suppoorted by QEMU Virt platform
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

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= 1

core-platform-cppflags += -D_USE_SLAPORT_LIB


# Several CPU suppoorted
core-platform-cppflags += -DTEE_MULTI_CPU
# define flag to support booting from GDB
core-platform-cppflags += -DCONFIG_TEE_GDB_BOOT
CFG_NO_TA_HASH_SIGN ?= y

core-platform-cppflags += -DWITH_UART_DRV=1
