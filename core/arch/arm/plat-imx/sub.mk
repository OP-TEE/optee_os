global-incdirs-y += .
srcs-y += main.c

srcs-$(CFG_PL310) += imx_pl310.c
srcs-$(CFG_PSCI_ARM32) += psci.c

srcs-$(PLATFORM_FLAVOR_mx6qsabrelite) += a9_plat_init.S
srcs-$(PLATFORM_FLAVOR_mx6qsabresd) += a9_plat_init.S
srcs-$(PLATFORM_FLAVOR_mx6dlsabresd) += a9_plat_init.S
srcs-$(PLATFORM_FLAVOR_mx6ulevk) += imx6ul.c
