include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_PREFIX	?= arm-linux-gnueabihf
CROSS_COMPILE	?= $(CROSS_PREFIX)-
COMPILER	?= gcc

core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-cppflags	+= -DNUM_THREADS=4
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
core-platform-subdirs += $(arch-dir)/sm

CFG_PM_DEBUG ?= 0
ifeq ($(CFG_PM_DEBUG),1)
core-platform-cppflags += \
	-DCFG_PM_DEBUG
endif

libutil_with_isoc := y
WITH_SECURE_TIME_SOURCE_CNTPCT := y
CFG_WITH_SEC_MON := y
CFG_WITH_STACK_CANARIES := y

include mk/config.mk

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= 1
core-platform-cppflags += \
	-DCFG_TEE_CORE_EMBED_INTERNAL_TESTS=$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS)

core-platform-cppflags += -DTEE_USE_DLMALLOC
core-platform-cppflags += -D_USE_SLAPORT_LIB


# Several CPU suppoorted
core-platform-cppflags += -DTEE_MULTI_CPU
# define flag to support booting from GDB
core-platform-cppflags += -DCONFIG_TEE_GDB_BOOT
core-platform-cppflags += -DCFG_NO_TA_HASH_SIGN
core-platform-cppflags += -DWITH_UART_DRV=1
WITH_SUNXI_UART := y
WITH_GIC_DRV := y
