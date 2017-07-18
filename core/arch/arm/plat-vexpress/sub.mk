global-incdirs-y += .
srcs-y += main.c
ifeq ($(PLATFORM_FLAVOR_juno),y)
srcs-$(CFG_ARM32_core) += juno_core_pos_a32.S
srcs-$(CFG_ARM64_core) += juno_core_pos_a64.S
endif
srcs-$(CFG_WITH_USER_TA) += vendor_props.c
