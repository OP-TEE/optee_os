srcs-y += drvcrypt_init.c

subdirs-$(CFG_CRYPTO_DRV_HASH)   += hash
subdirs-$(CFG_CRYPTO_DRV_CIPHER) += cipher
