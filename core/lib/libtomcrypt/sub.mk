global-incdirs-y += include
global-incdirs-y += src/headers

cflags-lib-y += -Wno-declaration-after-statement

cppflags-lib-y += -DARGTYPE=4  # Make LTC_ARGCHK() return on error
cppflags-lib-y += -DLTC_CLEAN_STACK -DLTC_NO_TEST -DLTC_NO_PROTOTYPES
cppflags-lib-y += -DLTC_NO_TABLES -DLTC_HASH_HELPERS
cppflags-lib-$(_CFG_CORE_LTC_SIZE_OPTIMIZATION) += -DLTC_SMALL_CODE

cppflags-lib-y += -DLTC_NO_CIPHERS

ifeq ($(_CFG_CORE_LTC_AES_DESC),y)
	cppflags-lib-y += -DLTC_RIJNDAEL
endif
ifeq ($(_CFG_CORE_LTC_DES),y)
	cppflags-lib-y += -DLTC_DES
endif

cppflags-lib-y += -DLTC_NO_MODES

ifeq ($(_CFG_CORE_LTC_ECB),y)
	cppflags-lib-y += -DLTC_ECB_MODE
endif
ifeq ($(_CFG_CORE_LTC_CBC),y)
	cppflags-lib-y += -DLTC_CBC_MODE
endif
ifeq ($(_CFG_CORE_LTC_CTR),y)
	cppflags-lib-y += -DLTC_CTR_MODE
endif
ifeq ($(_CFG_CORE_LTC_XTS),y)
	cppflags-lib-y += -DLTC_XTS_MODE
endif

cppflags-lib-y += -DLTC_NO_HASHES

ifeq ($(_CFG_CORE_LTC_MD5),y)
	cppflags-lib-y += -DLTC_MD5
endif
ifeq ($(_CFG_CORE_LTC_SHA1),y)
	cppflags-lib-y += -DLTC_SHA1
endif
ifeq ($(_CFG_CORE_LTC_SHA224),y)
	cppflags-lib-y += -DLTC_SHA224
endif
ifeq ($(_CFG_CORE_LTC_SHA256_DESC),y)
	cppflags-lib-y += -DLTC_SHA256
endif
ifeq ($(_CFG_CORE_LTC_SHA384_DESC),y)
	cppflags-lib-y += -DLTC_SHA384
endif
ifeq ($(_CFG_CORE_LTC_SHA512_DESC),y)
	cppflags-lib-y += -DLTC_SHA512
endif
ifeq ($(_CFG_CORE_LTC_SHA512_256),y)
	cppflags-lib-y += -DLTC_SHA512_256
endif

cppflags-lib-y += -DLTC_NO_MACS

ifeq ($(_CFG_CORE_LTC_HMAC),y)
	cppflags-lib-y += -DLTC_HMAC
endif
ifeq ($(_CFG_CORE_LTC_CMAC),y)
	cppflags-lib-y += -DLTC_OMAC
endif
ifeq ($(_CFG_CORE_LTC_CCM),y)
	cppflags-lib-y += -DLTC_CCM_MODE
endif
ifeq ($(_CFG_CORE_LTC_GCM),y)
	cppflags-lib-y += -DLTC_GCM_MODE
endif

cppflags-lib-y += -DLTC_NO_PK

ifeq ($(_CFG_CORE_LTC_RSA),y)
   cppflags-lib-y += -DLTC_MRSA
endif
ifeq ($(_CFG_CORE_LTC_DSA),y)
   cppflags-lib-y += -DLTC_MDSA
endif
ifeq ($(_CFG_CORE_LTC_DH),y)
   cppflags-lib-y += -DLTC_MDH
endif
ifeq ($(_CFG_CORE_LTC_ECC),y)
   cppflags-lib-y += -DLTC_MECC

   # use Shamir's trick for point mul (speeds up signature verification)
   cppflags-lib-y += -DLTC_ECC_SHAMIR

   cppflags-lib-y += -DLTC_ECC192
   cppflags-lib-y += -DLTC_ECC224
   cppflags-lib-y += -DLTC_ECC256
   cppflags-lib-y += -DLTC_ECC384
   cppflags-lib-y += -DLTC_ECC521

   # ECC 521 bits is the max supported key size
   cppflags-lib-y += -DLTC_MAX_ECC=521
endif
ifneq (,$(filter y,$(_CFG_CORE_LTC_SM2_DSA) $(_CFG_CORE_LTC_SM2_PKE)))
   cppflags-lib-y += -DLTC_ECC_SM2
endif

cppflags-lib-y += -DLTC_NO_PKCS

cppflags-lib-y += -DLTC_DER

cppflags-lib-y += -DLTC_NO_PRNGS -DLTC_FORTUNA

cflags-lib-$(_CFG_CORE_LTC_SIZE_OPTIMIZATION) += -Os

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
srcs-$(_CFG_CORE_LTC_AES_ACCEL) += aes_accel.c
srcs-$(_CFG_CORE_LTC_SHA1_ACCEL) += sha1_accel.c
ifeq ($(_CFG_CORE_LTC_SHA256_DESC),y)
srcs-$(_CFG_CORE_LTC_SHA256_ACCEL) += sha256_accel.c
endif
srcs-$(_CFG_CORE_LTC_SM2_DSA) += sm2-dsa.c
srcs-$(_CFG_CORE_LTC_SM2_PKE) += sm2-pke.c
srcs-$(_CFG_CORE_LTC_SM2_KEP) += sm2-kep.c

ifeq ($(_CFG_CORE_LTC_ACIPHER),y)
srcs-y += mpi_desc.c
endif

srcs-y += tomcrypt.c

