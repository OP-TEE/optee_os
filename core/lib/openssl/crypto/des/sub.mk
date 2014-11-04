incdirs-y := .. ../.. ../../include
cflags-remove-y += -Wswitch-default -Wmissing-prototypes
cflags-remove-y += -Wmissing-declarations
cflags-y += -Wno-sign-compare

srcs-y += cbc_enc.c
srcs-y += cbc3_enc.c
srcs-y += des_enc.c
srcs-y += ecb3_enc.c
srcs-y += ecb_enc.c
srcs-y += set_key.c
