global-incdirs-y += .
srcs-y += main.c
srcs-y += platform.c

ifeq ($(PLATFORM_FLAVOR),rk322x)
srcs-y += plat_init.S
srcs-y += core_pos_a32.S
srcs-$(CFG_PSCI_ARM32) += psci_rk322x.c
endif
