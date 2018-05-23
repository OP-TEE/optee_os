TOMCRYPT_SOURCE_PATH := ../../libtomcrypt
ifdef _CFG_CRYPTO_WITH_ACIPHER
srcs-y += $(TOMCRYPT_SOURCE_PATH)/src/mpa_desc.c
# Get mpa.h which normally is an internal .h file
cppflags-y += -Ilib/libmpa
cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-unused-parameter
endif

srcs-y += tee_ltc_provider.c

ifdef CFG_CRYPTO_MBEDTLS
subdirs-$(_CFG_CRYPTO_WITH_CIPHER) += $(TOMCRYPT_SOURCE_PATH)/src/ciphers
subdirs-y += $(TOMCRYPT_SOURCE_PATH)/src/hashes
subdirs-$(_CFG_CRYPTO_WITH_MAC) += $(TOMCRYPT_SOURCE_PATH)/src/mac
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += $(TOMCRYPT_SOURCE_PATH)/src/math
subdirs-y += $(TOMCRYPT_SOURCE_PATH)/src/misc
subdirs-y += $(TOMCRYPT_SOURCE_PATH)/src/modes
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += $(TOMCRYPT_SOURCE_PATH)/src/pk
subdirs-$(CFG_WITH_SOFTWARE_PRNG) += $(TOMCRYPT_SOURCE_PATH)/src/prngs
endif
