incdirs-y := .. ../.. ../../include ../asn1 ../evp

cflags-remove-y := -Wcast-align
cflags-y := -Wno-empty-body -Wno-unused-parameter

srcs-y += rsa_crpt.c
srcs-y += rsa_eay.c
srcs-y += rsa_gen.c
srcs-y += rsa_lib.c
srcs-y += rsa_none.c
srcs-y += rsa_oaep.c
srcs-y += rsa_pk1.c
srcs-y += rsa_pmeth.c
srcs-y += rsa_pss.c
srcs-y += rsa_sign.c
