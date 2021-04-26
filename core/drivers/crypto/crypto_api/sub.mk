srcs-y += drvcrypt.c

subdirs-y += math

subdirs-$(CFG_CRYPTO_DRV_HASH)    += hash
subdirs-$(CFG_CRYPTO_DRV_ACIPHER) += acipher
subdirs-$(CFG_CRYPTO_DRV_ACIPHER) += oid
subdirs-$(CFG_CRYPTO_DRV_CIPHER) += cipher
subdirs-$(CFG_CRYPTO_DRV_MAC) += mac
subdirs-$(CFG_CRYPTO_DRV_AUTHENC) += authenc
