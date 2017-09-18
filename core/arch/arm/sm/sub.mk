srcs-y += sm_a32.S
srcs-y += sm.c
srcs-$(CFG_PSCI_ARM32) += std_smc.c psci.c pm.c psci-helper.S pm_a32.S
