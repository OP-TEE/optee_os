global-incdirs-y += .
srcs-y += main.c imx-common.c

srcs-$(CFG_MX6)$(CFG_MX7) += mmdc.c

srcs-$(CFG_PL310) += imx_pl310.c
ifeq ($(CFG_PSCI_ARM32),y)
srcs-y += pm/psci.c pm/gpcv2.c
srcs-$(CFG_MX7) += pm/pm-imx7.c pm/psci-suspend-imx7.S pm/imx7_suspend.c
$(call force,CFG_PM_ARM32,y)
endif

cflags-pm/psci.c-y += -Wno-suggest-attribute=noreturn

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
       $(CFG_MX6SX)))
srcs-y += a9_plat_init.S imx6.c
endif

ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
srcs-y += imx6ul.c
endif

srcs-$(CFG_MX7) += imx7.c a7_plat_init.S
