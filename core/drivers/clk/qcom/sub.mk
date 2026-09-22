global-incdirs-y += .
global-incdirs-y += platform/$(PLATFORM_FLAVOR)

srcs-y += clk.c
srcs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)/clock-pas.c

ifeq ($(CFG_QCOM_CLK_CFG),y)
srcs-y += platform/$(PLATFORM_FLAVOR)/clk_cfg.c
srcs-y += clk_ops.c
srcs-$(CFG_QCOM_RPMH_CLIENT) += rail_rpmh.c
endif

incdirs-y += .
incdirs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)
incdirs-$(CFG_QCOM_CLK_CFG) += platform/$(PLATFORM_FLAVOR)
