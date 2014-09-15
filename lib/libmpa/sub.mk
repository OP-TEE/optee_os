global-incdirs-y += include

srcs-y += mpa_misc.c
cflags-remove-mpa_misc.c-y += -pedantic
cflags-mpa_misc.c-y += -Wno-sign-compare

srcs-y += mpa_montgomery.c
cflags-remove-mpa_montgomery.c-y += -Wdeclaration-after-statement
cflags-mpa_montgomery.c-y += -fno-strict-aliasing

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
srcs-y += mpa_debug.c
srcs-y += mpa_expmod.c
cflags-mpa_expmod.c-y += -fno-strict-aliasing
srcs-y += mpa_init.c
cflags-mpa_init.c-y += -fno-strict-aliasing
srcs-y += mpa_io.c
srcs-y += mpa_modulus.c

subdirs-(arch_arm32) += arch/$(ARCH)
