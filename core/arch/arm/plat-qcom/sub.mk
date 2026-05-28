global-incdirs-y += .
global-incdirs-y += $(QCOM_ARCH_FAMILY)
global-incdirs-y += $(QCOM_ARCH_FAMILY)/$(PLATFORM_FLAVOR)
srcs-y += main.c

$(eval $(call cfg-depends-all,CFG_QCOM_QFPROM_FUSEPROV,CFG_QCOM_QFPROM))
subdirs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision
