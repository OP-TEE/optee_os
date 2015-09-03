CFG_CRYPTO ?= y

ifeq (y,$(CFG_CRYPTO))

# HMAC-based Extract-and-Expand Key Derivation Function
# http://tools.ietf.org/html/rfc5869
# This is an OP-TEE extension, not part of the GlobalPlatform Internal API v1.0
CFG_CRYPTO_HKDF ?= y

# NIST SP800-56A Concatenation Key Derivation Function
# This is an OP-TEE extension
CFG_CRYPTO_CONCAT_KDF ?= y

# PKCS #5 v2.0 / RFC 2898 key derivation function 2
# This is an OP-TEE extension
CFG_CRYPTO_PBKDF2 ?= y

endif

srcs-y += tee_svc.c
srcs-y += tee_svc_cryp.c
srcs-y += tee_svc_storage.c
srcs-y += tee_cryp_utl.c
srcs-$(CFG_CRYPTO_HKDF) += tee_cryp_hkdf.c
srcs-$(CFG_CRYPTO_CONCAT_KDF) += tee_cryp_concat_kdf.c
srcs-$(CFG_CRYPTO_PBKDF2) += tee_cryp_pbkdf2.c

ifeq (y,$(CFG_RPMB_FS))
srcs-y += tee_rpmb_fs_common.c
else
srcs-y += tee_fs_common.c
endif

ifeq (y,$(CFG_ENC_FS))
srcs-y += tee_enc_fs_key_manager.c
srcs-y += tee_enc_fs.c
else
srcs-y += tee_fs.c
endif

srcs-y += tee_obj.c
srcs-y += tee_pobj.c
srcs-y += tee_rpmb_fs.c
srcs-y += tee_time_generic.c
srcs-y += abi.c

subdirs-${CFG_SE_API} += se
