global-incdirs-y += .
srcs-$(CFG_ARM32_core) += entry_a32.S
srcs-y += main.c
srcs-y += plat_tee_func.c
srcs-y += tee_common_otp.c
srcs-y += core_bootcfg.c
srcs-y += core_chip.c
srcs-$(PLATFORM_FLAVOR_juno) += juno_core_pos_a32.S
