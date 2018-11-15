global-incdirs-y += include

srcs-y += mpa_misc.c
cflags-remove-mpa_misc.c-y += -pedantic
cflags-mpa_misc.c-y += -Wno-sign-compare

srcs-y += mpa_montgomery.c

srcs-y += mpa_primetest.c
cflags-remove-mpa_primetest.c-y += -pedantic

srcs-y += mpa_conv.c
cflags-mpa_conv.c-y += -Wno-sign-compare

srcs-y += mpa_div.c
cflags-mpa_div.c-y += -Wno-sign-compare

srcs-y += mpa_gcd.c
cflags-mpa_gcd.c-y += -Wno-sign-compare

srcs-y += mpa_mem_static.c
cflags-mpa_mem_static.c-y += -Wno-sign-compare

srcs-y += mpa_mul.c
cflags-mpa_mul.c-y += -Wno-sign-compare

srcs-y += mpa_random.c
cflags-mpa_random.c-y += -Wno-sign-compare

srcs-y += mpa_shift.c
cflags-mpa_shift.c-y += -Wno-sign-compare

srcs-y += mpa_addsub.c
srcs-y += mpa_cmp.c
srcs-y += mpa_expmod.c
srcs-y += mpa_init.c
srcs-y += mpa_io.c
srcs-y += mpa_modulus.c

subdirs-$(arch_arm) += arch/$(ARCH)
