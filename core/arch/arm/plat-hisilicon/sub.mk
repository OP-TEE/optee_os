global-incdirs-y += .
srcs-y += main.c
srcs-$(CFG_HI3519AV100) += hi3519av100_plat_init.S
srcs-$(CFG_PSCI_ARM32) += psci.c
