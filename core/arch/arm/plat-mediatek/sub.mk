global-incdirs-y += .
srcs-y += main.c
ifeq ($(PLATFORM_FLAVOR),mt8173)
srcs-$(CFG_ARM32_core) += mt8173_core_pos_a32.S
srcs-$(CFG_ARM64_core) += mt8173_core_pos_a64.S
endif
