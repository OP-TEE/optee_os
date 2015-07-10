srcs-$(CFG_CRYPTO_MD5) += md5.c

ifeq ($(CFG_CRYPTO_SHA1),y)
SHA1_CE := $(call cfg-one-enabled, CFG_CRYPTO_SHA1_ARM32_CE CFG_CRYPTO_SHA1_ARM64_CE)
ifeq ($(SHA1_CE),y)
srcs-y += sha1_armv8a_ce.c
srcs-$(CFG_CRYPTO_SHA1_ARM32_CE) += sha1_armv8a_ce_a32.S
srcs-$(CFG_CRYPTO_SHA1_ARM64_CE) += sha1_armv8a_ce_a64.S
else
srcs-y += sha1.c
endif
endif

subdirs-y += helper
subdirs-y += sha2
