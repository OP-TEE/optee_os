global-incdirs-y += .
srcs-y += main.c
srcs-$(CFG_ARM32_core) += core_pos_a32.S
srcs-$(CFG_ARM64_core) += core_pos_a64.S
