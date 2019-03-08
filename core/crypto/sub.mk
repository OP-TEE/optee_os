srcs-y += crypto.c
srcs-y += aes-gcm.c
srcs-y += aes-gcm-sw.c
ifeq ($(CFG_AES_GCM_TABLE_BASED),y)
srcs-y += aes-gcm-ghash-tbl.c
else
srcs-y += aes-gcm-ghash.c
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
