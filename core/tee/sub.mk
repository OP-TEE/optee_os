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

srcs-y += entry_std.c
srcs-y += tee_cryp_utl.c
srcs-$(CFG_CRYPTO_HKDF) += tee_cryp_hkdf.c
srcs-$(CFG_CRYPTO_CONCAT_KDF) += tee_cryp_concat_kdf.c
ifneq ($(CFG_CRYPTO_HW_PBKDF2),y)
srcs-$(CFG_CRYPTO_PBKDF2) += tee_cryp_pbkdf2.c
endif

ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += tee_obj.c
srcs-y += tee_svc.c
srcs-y += tee_svc_cryp.c
srcs-y += tee_svc_storage.c
cppflags-tee_svc.c-y += -DTEE_IMPL_VERSION=$(TEE_IMPL_VERSION)
srcs-y += tee_time_generic.c
srcs-$(CFG_SECSTOR_TA) += tadb.c
srcs-$(CFG_GP_SOCKETS) += socket.c
srcs-y += tee_ta_enc_manager.c
endif #CFG_WITH_USER_TA,y

srcs-$(_CFG_WITH_SECURE_STORAGE) += tee_fs_key_manager.c
srcs-$(CFG_RPMB_FS) += tee_rpmb_fs.c
srcs-$(CFG_REE_FS) += tee_ree_fs.c
srcs-$(CFG_REE_FS) += fs_dirfile.c
srcs-$(CFG_REE_FS) += fs_htree.c
srcs-$(CFG_REE_FS) += tee_fs_rpc.c

ifeq ($(call cfg-one-enabled,CFG_WITH_USER_TA _CFG_WITH_SECURE_STORAGE),y)
srcs-y += tee_pobj.c
endif

srcs-y += uuid.c
srcs-y += tee_supp_plugin_rpc.c
