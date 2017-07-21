global-incdirs-y += .
srcs-y += main.c
srcs-y += platform.c
srcs-y += plat_init.S

srcs-$(CFG_ARM32_core) += core_pos_a32.S

ifeq ($(PLATFORM_FLAVOR),rk322x)
srcs-$(CFG_PSCI_ARM32) += psci_rk322x.c
endif
