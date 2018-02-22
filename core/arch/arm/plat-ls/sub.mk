global-incdirs-y += .
srcs-y += main.c
srcs-$(CFG_ARM32_core) += ls_core_pos_a32.S
srcs-$(CFG_ARM64_core) += ls_core_pos_a64.S
srcs-$(CFG_ARM64_core) += ls_hw_unq_key_a64.S
srcs-$(CFG_ARM32_core) += plat_init.S
