global-incdirs-y += .

srcs-y += clock-qcom.c clock-qcom-pas.c
incdirs-y += .
incdirs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)
