global-incdirs-y += .
srcs-y += main.c imx-common.c

srcs-$(CFG_PL310) += imx_pl310.c
srcs-$(CFG_PSCI_ARM32) += psci.c gpcv2.c
cflags-psci.c-y += -Wno-suggest-attribute=noreturn

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL)))
srcs-y += a9_plat_init.S imx6.c
endif

ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
srcs-y += imx6ul.c
endif

srcs-$(CFG_MX7) += imx7.c a7_plat_init.S
