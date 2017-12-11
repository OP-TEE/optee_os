global-incdirs-y += .
global-incdirs-y += registers

srcs-y += main.c
srcs-$(CFG_MX6)$(CFG_MX7) += imx-common.c mmdc.c
srcs-$(CFG_MX7) += gpcv2.c

srcs-$(CFG_PL310) += imx_pl310.c
ifeq ($(CFG_PSCI_ARM32),y)
srcs-y += pm/psci.c
srcs-$(CFG_MX7) += pm/pm-imx7.c pm/psci-suspend-imx7.S pm/imx7_suspend.c
$(call force,CFG_PM_ARM32,y)
asm-defines-y += imx_pm_asm_defines.c
endif

cflags-pm/psci.c-y += -Wno-suggest-attribute=noreturn

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6QP) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
	$(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX)))
srcs-y += a9_plat_init.S
endif

ifneq (,$(filter y, $(CFG_MX7) $(CFG_MX7ULP) $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
endif

srcs-$(CFG_TZC380) += tzasc.c
srcs-$(CFG_CSU) += imx_csu.c
srcs-$(CFG_SCU) += imx_scu.c
