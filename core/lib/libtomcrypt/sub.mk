cppflags-lib-$(_CFG_CORE_LTC_SIZE_OPTIMIZATION) += -DLTC_SMALL_CODE
cppflags-lib-y += -DLTC_RSA_CRT_HARDENING -DLTC_RSA_BLINDING -DLTC_CLEAN_STACK

global-incdirs-y += include

subdirs-y += src

srcs-$(_CFG_CORE_LTC_HASH) += hash.c
srcs-$(_CFG_CORE_LTC_HMAC) += hmac.c
srcs-$(_CFG_CORE_LTC_CMAC) += cmac.c
srcs-$(_CFG_CORE_LTC_ECB) += ecb.c
srcs-$(_CFG_CORE_LTC_CBC) += cbc.c
srcs-$(_CFG_CORE_LTC_CTR) += ctr.c
srcs-$(_CFG_CORE_LTC_XTS) += xts.c
srcs-$(_CFG_CORE_LTC_CCM) += ccm.c
srcs-$(_CFG_CORE_LTC_GCM) += gcm.c
srcs-$(_CFG_CORE_LTC_DSA) += dsa.c
srcs-$(_CFG_CORE_LTC_ECC) += ecc.c
srcs-$(_CFG_CORE_LTC_RSA) += rsa.c
srcs-$(_CFG_CORE_LTC_DH) += dh.c
srcs-$(_CFG_CORE_LTC_AES) += aes.c

ifdef _CFG_CORE_LTC_ACIPHER
ifeq ($(_CFG_CORE_LTC_MPI),y)
srcs-y += mpi_desc.c
else
srcs-y += mpa_desc.c
# Get mpa.h which normally is an internal .h file
cppflags-mpa_desc.c-y += -Ilib/libmpa
cflags-mpa_desc.c-y += -Wno-unused-parameter
endif
endif

srcs-y += tomcrypt.c

