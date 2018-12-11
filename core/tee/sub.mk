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

srcs-y += tee_cryp_utl.c
srcs-$(CFG_CRYPTO_HKDF) += tee_cryp_hkdf.c
srcs-$(CFG_CRYPTO_CONCAT_KDF) += tee_cryp_concat_kdf.c
srcs-$(CFG_CRYPTO_PBKDF2) += tee_cryp_pbkdf2.c

ifeq ($(CFG_WITH_USER_TA),y)

srcs-y += tee_svc.c
cppflags-tee_svc.c-y += -DTEE_IMPL_VERSION=$(TEE_IMPL_VERSION)
srcs-y += tee_svc_cryp.c
srcs-y += tee_svc_storage.c
srcs-$(CFG_RPMB_FS) += tee_rpmb_fs.c
srcs-$(CFG_REE_FS) += tee_ree_fs.c
srcs-$(call cfg-one-enabled,CFG_REE_FS CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += \
	fs_htree.c
srcs-$(CFG_REE_FS) += fs_dirfile.c
srcs-$(CFG_REE_FS) += tee_fs_rpc.c
srcs-$(call cfg-one-enabled,CFG_REE_FS CFG_RPMB_FS) += tee_fs_rpc_cache.c
srcs-y += tee_fs_key_manager.c
srcs-y += tee_obj.c
srcs-y += tee_pobj.c
srcs-y += tee_time_generic.c

srcs-$(CFG_SECSTOR_TA) += tadb.c

endif #CFG_WITH_USER_TA,y

srcs-y += uuid.c
