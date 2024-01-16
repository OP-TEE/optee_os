global-incdirs-y += .
srcs-y += main.c imx-common.c

srcs-$(CFG_PL310) += imx_pl310.c
ifeq ($(CFG_PSCI_ARM32),y)
$(call force,CFG_PM_ARM32,y)
CFG_IMX_PM ?= y
endif

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6QP) $(CFG_MX6D) $(CFG_MX6DL) \
	$(CFG_MX6S) $(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX)))
srcs-y += a9_plat_init.S
srcs-$(CFG_SM_PLATFORM_HANDLER) += sm_platform_handler.c
endif

ifneq (,$(filter y, $(CFG_MX7) $(CFG_MX7ULP) $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
endif

srcs-$(CFG_TZC380) += tzc380.c
