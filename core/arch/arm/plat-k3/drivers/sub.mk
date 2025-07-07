
srcs-y += ti_sci.c

ifeq ($(PLATFORM_FLAVOR),am62lx)
srcs-y += mailbox.c
else
srcs-y += sec_proxy.c
endif

srcs-$(CFG_SA2UL) += sa2ul.c
srcs-$(CFG_SA2UL) += sa2ul_rng.c
