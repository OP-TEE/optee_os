srcs-$(CFG_CRYPTO_MD5) += md5.c

ifeq ($(CFG_CRYPTO_SHA1_ARM32_CE),y)
srcs-y += sha1_arm32_ce.c
srcs-y += sha1_arm32_ce_a32.S
else
srcs-$(CFG_CRYPTO_SHA1) += sha1.c
endif

subdirs-y += helper
subdirs-y += sha2
