global-incdirs-y += .
srcs-y += main.c
srcs-y += platform.c
srcs-$(PLATFORM_FLAVOR_px30) += platform_px30.c
srcs-$(PLATFORM_FLAVOR_rk322x) += platform_rk322x.c
srcs-$(PLATFORM_FLAVOR_rk3399) += platform_rk3399.c

ifeq ($(PLATFORM_FLAVOR),rk322x)
srcs-y += plat_init.S
srcs-y += core_pos_a32.S
srcs-$(CFG_PSCI_ARM32) += psci_rk322x.c
endif
