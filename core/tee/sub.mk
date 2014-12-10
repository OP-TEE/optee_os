CFG_CRYPTO ?= y

ifeq (y,$(CFG_CRYPTO))
# NIST SP800-56A Concatenation Key Derivation Function
# This is an OP-TEE extension
CFG_CRYPTO_CONCAT_KDF ?= y
endif

srcs-y += tee_svc.c
srcs-y += tee_svc_cryp.c
srcs-y += tee_svc_storage.c

srcs-y += tee_cryp_utl.c
srcs-$(CFG_CRYPTO_CONCAT_KDF) += tee_cryp_concat_kdf.c
srcs-y += tee_fs.c
srcs-y += tee_obj.c
srcs-y += tee_pobj.c
srcs-y += tee_rpmb_fs.c
srcs-y += tee_time_generic.c
