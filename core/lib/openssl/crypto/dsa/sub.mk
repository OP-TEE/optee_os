incdirs-y := .. ../.. ../../include ../asn1 ../evp

cflags-y := -Wno-unused-parameter

srcs-y += dsa_gen.c
srcs-y += dsa_key.c
srcs-y += dsa_lib.c
srcs-y += dsa_ossl.c
srcs-y += dsa_sign.c
srcs-y += dsa_vrf.c
