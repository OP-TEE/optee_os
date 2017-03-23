global-incdirs-y += .
srcs-y += main.c

srcs-$(CFG_PL310) += imx_pl310.c
srcs-$(CFG_PSCI_ARM32) += psci.c

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL)))
srcs-y += a9_plat_init.S imx6.c
endif

srcs-$(CFG_MX6UL) += imx6ul.c
