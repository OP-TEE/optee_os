ifdef _CFG_CRYPTO_WITH_ACIPHER
ifeq ($(CFG_CORE_MBEDTLS_MPI),y)
srcs-y += mpi_desc.c
else
srcs-y += mpa_desc.c
# Get mpa.h which normally is an internal .h file
cppflags-mpa_desc.c-y += -Ilib/libmpa
cflags-mpa_desc.c-y += -Wno-unused-parameter
endif
endif

srcs-y += tee_ltc_provider.c

subdirs-$(_CFG_CRYPTO_WITH_CIPHER) += ciphers
subdirs-$(_CFG_CRYPTO_WITH_AUTHENC) += encauth
subdirs-y += hashes
subdirs-$(_CFG_CRYPTO_WITH_MAC) += mac
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += math
subdirs-y += misc
subdirs-y += modes
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += pk
