global-incdirs-y += .
srcs-y += main.c
srcs-$(PLATFORM_FLAVOR_mx6qsabrelite) += a9_plat_init.S
srcs-$(PLATFORM_FLAVOR_mx6qsabresd) += a9_plat_init.S
