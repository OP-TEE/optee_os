global-incdirs-y += .
global-incdirs-y += platform/$(PLATFORM_FLAVOR)

srcs-y += clock-qcom.c
srcs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)/clock-qcom-pas.c

incdirs-y += .
incdirs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)
