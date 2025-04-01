srcs-y += imx_mu.c
srcs-$(call cfg-one-enabled,CFG_MX8ULP CFG_MX93 CFG_MX91 CFG_MX95 CFG_MX943) += imx_mu_8ulp_9x.c
ifeq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX) $(CFG_MX8DXL)),y)
srcs-y += imx_mu_8q.c
endif
