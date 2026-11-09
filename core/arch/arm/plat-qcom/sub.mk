global-incdirs-y += .
global-incdirs-y += $(QCOM_ARCH_FAMILY)
global-incdirs-y += $(QCOM_ARCH_FAMILY)/$(PLATFORM_FLAVOR)
srcs-y += main.c
srcs-$(CFG_QCOM_DIAG_LOG) += diag_log.c
srcs-$(CFG_QCOM_XPU_PROTECT) += xpu_policy.c

ifneq ($(filter y,$(CFG_QCOM_DIAG_LOG) $(CFG_QCOM_QFPROM_FUSEPROV)),)
srcs-y += boot_mode.c
endif

ifeq ($(CFG_QCOM_PROVISION_BACKEND_TME)-$(CFG_QCOM_QFPROM_FUSEPROV),y-y)
# The security processor is reached through the FF-A SPMC at EL3
ifneq ($(CFG_CORE_EL3_SPMC),y)
$(error CFG_QCOM_PROVISION_BACKEND=tme needs CFG_CORE_EL3_SPMC=y)
endif
endif

subdirs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision
subdirs-y += $(QCOM_ARCH_FAMILY)
