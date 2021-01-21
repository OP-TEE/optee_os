srcs-y += crypto.c

srcs-y += aes-gcm.c
ifneq ($(CFG_CRYPTO_WITH_CE),y)
srcs-y += aes-gcm-sw.c
ifeq ($(CFG_AES_GCM_TABLE_BASED),y)
srcs-y += aes-gcm-ghash-tbl.c
endif
endif

srcs-$(CFG_WITH_USER_TA) += signed_hdr.c

ifeq ($(CFG_WITH_SOFTWARE_PRNG),y)
srcs-y += rng_fortuna.c
else
srcs-y += rng_hw.c
endif

ifneq ($(CFG_CRYPTO_CBC_MAC_FROM_CRYPTOLIB),y)
srcs-$(CFG_CRYPTO_CBC_MAC) += cbc-mac.c
endif
ifneq ($(CFG_CRYPTO_CTS_FROM_CRYPTOLIB),y)
srcs-$(CFG_CRYPTO_CTS) += aes-cts.c
endif
ifneq (,$(filter y,$(CFG_CRYPTO_SM2_PKE) $(CFG_CRYPTO_SM2_KEP)))
srcs-y += sm2-kdf.c
endif
ifeq ($(CFG_CRYPTO_SM3),y)
srcs-y += sm3.c
srcs-y += sm3-hash.c
srcs-$(CFG_CRYPTO_HMAC) += sm3-hmac.c
endif
ifeq ($(CFG_CRYPTO_SM4),y)
srcs-y += sm4.c
srcs-$(CFG_CRYPTO_ECB) += sm4-ecb.c
srcs-$(CFG_CRYPTO_CBC) += sm4-cbc.c
srcs-$(CFG_CRYPTO_CTR) += sm4-ctr.c
endif
