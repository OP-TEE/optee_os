
srcs-y += ti_sci.c
srcs-$(CFG_EIP76D_TRNG) += eip76d_trng.c
ifeq ($(PLATFORM_FLAVOR),am62lx)
srcs-y += mailbox.c
else
srcs-y += sec_proxy.c
endif

srcs-$(CFG_SA2UL) += sa2ul.c
srcs-$(CFG_DTHEV2) += dthev2.c
