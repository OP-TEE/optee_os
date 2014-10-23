incdirs-y := .. ../.. ../../include

cflags-remove-y := -Wcast-align -Wswitch-default
cflags-y := -Wno-unused-parameter

srcs-y += bn_add.c
srcs-y += bn_asm.c
srcs-y += bn_blind.c
srcs-y += bn_ctx.c
srcs-y += bn_div.c
srcs-y += bn_exp.c
srcs-y += bn_exp2.c
srcs-y += bn_gcd.c
srcs-y += bn_lib.c
srcs-y += bn_mod.c
srcs-y += bn_mont.c
srcs-y += bn_mul.c
srcs-y += bn_prime.c
srcs-y += bn_rand.c
srcs-y += bn_recp.c
srcs-y += bn_shift.c
srcs-y += bn_sqr.c
srcs-y += bn_word.c
