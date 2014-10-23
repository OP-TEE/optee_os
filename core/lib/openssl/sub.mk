cppflags-lib-y += -DGETPID_IS_MEANINGLESS
cppflags-lib-y += -DOPENSSL_NO_DEPRECATED
cppflags-lib-y += -DOPENSSL_NO_ENGINE
cppflags-lib-y += -DOPENSSL_NO_ERR
cppflags-lib-y += -DOPENSSL_NO_FP_API
cppflags-lib-y += -DOPENSSL_NO_LOCKING
cppflags-lib-y += -DOPENSSL_NO_STDIO

# OP-TEE-specific defines to remove some unused features
cppflags-lib-y += -DOPTEE
cppflags-lib-y += -DOPTEE_OPENSSL_NO_EX_DATA
cppflags-lib-y += -DOPTEE_OPENSSL_NO_MEM_DBG
cppflags-lib-y += -DOPTEE_OPENSSL_NO_PKCS12
cppflags-lib-y += -DOPTEE_OPENSSL_NO_RSA_X931_PADDING
cppflags-lib-y += -DOPTEE_OPENSSL_NO_SSLV23_PADDING

# Enable custom modification in AES-XTS
cppflags-lib-y += -DOPTEE_OPENSSL_AES_XTS_MULTIPLE_UPDATES

# Eliminate unused symbols:
# 1. Tell compiler to place each data/function item in its own section
cflags-lib-y += -fdata-sections -ffunction-sections
# 2. Tell lib.mk to use $(LD) rather than $(AR)
lib-use-ld := y
# 3. Tell $(LD) to perform incremental link, keeping symbol 'crypto_ops' and
# its dependencies, then discarding unreferenced symbols
lib-ldflags := -i --gc-sections -u crypto_ops

incdirs-lib-y := ../../include
incdirs-y := include

srcs-y += tee_ossl_provider.c

subdirs-y += crypto
