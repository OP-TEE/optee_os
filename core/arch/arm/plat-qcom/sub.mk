global-incdirs-y += .
srcs-y += main.c

$(eval $(call cfg-depends-all,CFG_QFPROM_PROGRAMMING,CFG_QCOM_QFPROM))
subdirs-$(CFG_QFPROM_PROGRAMMING) += provision
