include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee) $(platform-dir)

$(call force,CFG_8250_UART,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
$(call force,CFG_MMU_V7_TTB,y)
endif

libtomcrypt_with_optimize_size ?= y
CFG_WITH_STACK_CANARIES ?= y

include mk/config.mk
