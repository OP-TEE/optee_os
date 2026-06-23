global-incdirs-y += .
global-incdirs-y += $(QCOM_ARCH_FAMILY)
global-incdirs-y += $(QCOM_ARCH_FAMILY)/$(PLATFORM_FLAVOR)
srcs-y += main.c
srcs-$(CFG_QCOM_DIAG_LOG) += diag_log.c

subdirs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision
subdirs-y += $(QCOM_ARCH_FAMILY)
