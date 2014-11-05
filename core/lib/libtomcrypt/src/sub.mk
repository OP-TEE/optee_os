srcs-y += mpa_desc.c
# Get mpa.h which normally is an internal .h file
cppflags-mpa_desc.c-y += -Ilib/libmpa
cflags-mpa_desc.c-y += -Wno-declaration-after-statement
cflags-mpa_desc.c-y += -Wno-unused-parameter

srcs-y += tee_ltc_provider.c

subdirs-y += ciphers
subdirs-y += encauth
subdirs-y += hashes
subdirs-y += mac
subdirs-y += math
subdirs-y += misc
subdirs-y += modes
subdirs-y += pk
subdirs-y += prngs
