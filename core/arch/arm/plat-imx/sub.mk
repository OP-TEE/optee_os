global-incdirs-y += .
srcs-y += main.c

srcs-$(CFG_MX6)$(CFG_MX7) += mmdc.c imx-common.c

srcs-$(CFG_PL310) += imx_pl310.c
ifeq ($(CFG_PSCI_ARM32),y)
$(call force,CFG_PM_ARM32,y)
asm-defines-y += imx_pm_asm_defines.c
endif

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
       $(CFG_MX6SX)))
srcs-y += a9_plat_init.S imx6.c
srcs-$(CFG_SM_PLATFORM_HANDLER) += sm_platform_handler.c
endif

ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
srcs-y += imx6ul.c
endif

srcs-$(CFG_MX7) += imx7.c a7_plat_init.S

subdirs-$(CFG_PSCI_ARM32) += pm

subdirs-y += drivers
