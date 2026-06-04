global-incdirs-y += .
srcs-y += main.c

$(eval $(call cfg-depends-all,CFG_QCOM_QFPROM_FUSEPROV,CFG_QCOM_QFPROM))
subdirs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision
