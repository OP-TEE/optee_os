global-incdirs-y += .
global-incdirs-y += family/$(QCOM_ARCH_FAMILY)
global-incdirs-y += family/$(QCOM_ARCH_FAMILY)/$(PLATFORM_FLAVOR)
srcs-y += main.c
srcs-$(CFG_QCOM_DIAG_LOG) += diag_log.c
ifeq ($(CFG_QCOM_XPU_PROTECT),y)
ifeq ($(CFG_EMBED_DTB),y)
srcs-y += xpu_policy_dt.c
else
srcs-y += xpu_policy_non_dt.c
endif
endif

ifneq ($(filter y,$(CFG_QCOM_DIAG_LOG) $(CFG_QCOM_QFPROM_FUSEPROV)),)
srcs-y += boot_mode.c
endif

subdirs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision
subdirs-y += family/$(QCOM_ARCH_FAMILY)
