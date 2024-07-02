incdirs-y += include

srcs-y += ipi.c
srcs-y += authenc.c
srcs-y += ecc.c
ifeq ($(CFG_VERSAL_PKI_DRIVER),y)
subdirs-y += pki
else
srcs-y += ecc_mbox.c
endif
srcs-y += rsa.c
