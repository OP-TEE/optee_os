global-incdirs-y += .
srcs-y += main.c
ifeq ($(PLATFORM_FLAVOR_juno),y)
srcs-$(CFG_ARM32_core) += juno_core_pos_a32.S
srcs-$(CFG_ARM64_core) += juno_core_pos_a64.S
endif
srcs-$(CFG_WITH_USER_TA) += vendor_props.c
ifeq ($(CFG_CORE_FFA),y)
ifeq ($(PLATFORM_FLAVOR_fvp),y)
srcs-$(CFG_ARM64_core) += fvp_spmc_pm.c
endif
ifeq ($(PLATFORM_FLAVOR_qemu_armv8a),y)
srcs-y += fvp_spmc_pm.c
endif
endif
