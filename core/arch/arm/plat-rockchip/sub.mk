global-incdirs-y += .
srcs-y += main.c
srcs-y += platform.c
srcs-$(PLATFORM_FLAVOR_px30) += platform_px30.c
srcs-$(PLATFORM_FLAVOR_rk322x) += platform_rk322x.c
srcs-$(PLATFORM_FLAVOR_rk3399) += platform_rk3399.c
srcs-$(PLATFORM_FLAVOR_rk3506) += platform_rk3506.c
srcs-$(PLATFORM_FLAVOR_rk3576) += platform_rk3576.c
srcs-$(PLATFORM_FLAVOR_rk3588) += platform_rk3588.c
srcs-$(PLATFORM_FLAVOR_rv1106) += platform_rv1106.c

ifneq ($(filter rk322x rv1106, $(PLATFORM_FLAVOR)),)
srcs-y += plat_init.S
srcs-y += core_pos_a32.S
endif

srcs-$(PLATFORM_FLAVOR_rk322x) += psci_rk322x.c

ifeq ($(PLATFORM_FLAVOR),rk3506)
# rk3506-specific plat_init programs CNTFRQ_EL0 (the RK3506 boot chain
# leaves it at its reset default) in addition to ACTLR.SMP; see the file
# header in plat_init_rk3506.S. core_pos_a32.S is reused from rk322x
# (same Rockchip 0xf0X MPIDR layout).
srcs-y += plat_init_rk3506.S
srcs-y += core_pos_a32.S
# PSCI back end (psci_rk3506.c) + position-independent secondary-core
# boot pen (pen_rk3506.S, copied into IRAM at init).
srcs-$(CFG_PSCI_ARM32) += psci_rk3506.c
srcs-$(CFG_PSCI_ARM32) += pen_rk3506.S
endif
