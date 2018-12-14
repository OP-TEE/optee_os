cflags-lib-$(CFG_CRYPTO_SIZE_OPTIMIZATION) += -Os

srcs-y += tee_lmd_provider.c

ifneq (,$(filter y, $(CFG_CRYPTO_DSA) $(CFG_CRYPTO_CTR) $(CFG_CRYPTO_XTS)))

ifeq ($(CFG_CRYPTO_DSA),y)
CFG_MBEDTLS_WITH_TOMCRYPT := y
endif

TOMCRYPTO_LIB_PATH := ../../../core/lib/libtomcrypt
global-incdirs-y += $(TOMCRYPTO_LIB_PATH)/include

srcs-$(CFG_CRYPTO_DSA) += $(TOMCRYPTO_LIB_PATH)/src/mpi_desc.c

subdirs-y += $(TOMCRYPTO_LIB_PATH)/src/hashes
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += $(TOMCRYPTO_LIB_PATH)/src/math
subdirs-y += $(TOMCRYPTO_LIB_PATH)/src/misc
subdirs-y += $(TOMCRYPTO_LIB_PATH)/src/modes
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += $(TOMCRYPTO_LIB_PATH)/src/pk
endif
