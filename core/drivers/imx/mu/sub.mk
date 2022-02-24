srcs-y += imx_mu.c
srcs-$(CFG_MX8ULP) += imx_mu_8ulp.c
ifeq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX)),y)
srcs-y += imx_mu_8q.c
endif
