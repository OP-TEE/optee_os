srcs-y += sm_a32.S
srcs-y += sm.c
srcs-$(CFG_PM_ARM32) += pm.c pm_a32.S
srcs-$(CFG_PSCI_ARM32) += std_smc.c psci.c psci-helper.S
