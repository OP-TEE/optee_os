global-incdirs-y += include
global-incdirs-y += src/headers

cppflags-lib-y += -DARGTYPE=4  # Make LTC_ARGCHK() return on error
cppflags-lib-y += -DLTC_NO_TEST -DLTC_NO_PROTOTYPES
cppflags-lib-y += -DLTC_NO_TABLES -DLTC_HASH_HELPERS
cppflags-lib-y += -DLTC_NO_MISC
cppflags-lib-y += -DLTC_HMAC
cppflags-lib-$(_CFG_CORE_LTC_SIZE_OPTIMIZATION) += -DLTC_SMALL_CODE
cppflags-lib-y += -DLTC_NO_CIPHERS
cppflags-lib-y += -DLTC_NO_MODES
cppflags-lib-y += -DLTC_NO_HASHES
cppflags-lib-y += -DLTC_NO_MACS
cppflags-lib-y += -DLTC_NO_PK
cppflags-lib-y += -DLTC_NO_PRNGS -DLTC_FORTUNA
cflags-lib-$(_CFG_CORE_LTC_SIZE_OPTIMIZATION) += -Os

srcs-y += tomcrypt.c
srcs-y += src/misc/burn_stack.c
srcs-y += src/misc/error_to_string.c
srcs-y += src/misc/mem_neq.c
srcs-y += src/misc/zeromem.c
srcs-y += src/misc/base64/base64_decode.c
srcs-y += src/misc/base64/base64_encode.c
srcs-y += src/misc/crypt/crypt.c
srcs-y += src/misc/crypt/crypt_cipher_descriptor.c
srcs-y += src/misc/crypt/crypt_cipher_is_valid.c
srcs-y += src/misc/crypt/crypt_find_cipher_any.c
srcs-y += src/misc/crypt/crypt_find_cipher.c
srcs-y += src/misc/crypt/crypt_find_cipher_id.c
srcs-y += src/misc/crypt/crypt_find_hash_any.c
srcs-y += src/misc/crypt/crypt_find_hash.c
srcs-y += src/misc/crypt/crypt_find_hash_id.c
srcs-y += src/misc/crypt/crypt_find_hash_oid.c
srcs-y += src/misc/crypt/crypt_find_prng.c
srcs-y += src/misc/crypt/crypt_fsa.c
srcs-y += src/misc/crypt/crypt_hash_descriptor.c
srcs-y += src/misc/crypt/crypt_hash_is_valid.c
srcs-y += src/misc/crypt/crypt_prng_descriptor.c
srcs-y += src/misc/crypt/crypt_prng_is_valid.c
srcs-y += src/misc/crypt/crypt_register_cipher.c
srcs-y += src/misc/crypt/crypt_register_hash.c
srcs-y += src/misc/crypt/crypt_register_prng.c
srcs-y += src/misc/crypt/crypt_unregister_cipher.c
srcs-y += src/misc/crypt/crypt_unregister_hash.c
srcs-y += src/misc/crypt/crypt_unregister_prng.c
srcs-y += src/misc/pkcs12/pkcs12_kdf.c
srcs-y += src/misc/pkcs12/pkcs12_utf8_to_utf16.c
srcs-y += src/misc/pkcs5/pkcs_5_1.c
srcs-y += src/misc/pkcs5/pkcs_5_2.c
srcs-y += src/misc/ssh/ssh_decode_sequence_multi.c
srcs-y += src/misc/ssh/ssh_encode_sequence_multi.c

cppflags-lib-$(_CFG_CORE_LTC_AES_DESC) += -DLTC_RIJNDAEL
srcs-$(_CFG_CORE_LTC_AES) += aes.c
ifeq ($(_CFG_CORE_LTC_AES_ACCEL),y)
srcs-$(_CFG_CORE_LTC_AES_DESC) += aes_accel.c
else
srcs-$(_CFG_CORE_LTC_AES_DESC) += src/ciphers/aes/aes.c
srcs-$(_CFG_CORE_LTC_AES_DESC) += src/ciphers/aes/aes_desc.c
endif

cppflags-lib-$(_CFG_CORE_LTC_DES) += -DLTC_DES
srcs-$(_CFG_CORE_LTC_DES) += src/ciphers/des.c

cppflags-lib-$(_CFG_CORE_LTC_CCM) += -DLTC_CCM_MODE
srcs-$(_CFG_CORE_LTC_CCM) += ccm.c
srcs-$(_CFG_CORE_LTC_CCM) += src/encauth/ccm/ccm_init.c
srcs-$(_CFG_CORE_LTC_CCM) += src/encauth/ccm/ccm_add_nonce.c
srcs-$(_CFG_CORE_LTC_CCM) += src/encauth/ccm/ccm_add_aad.c
srcs-$(_CFG_CORE_LTC_CCM) += src/encauth/ccm/ccm_process.c
srcs-$(_CFG_CORE_LTC_CCM) += src/encauth/ccm/ccm_done.c
srcs-$(_CFG_CORE_LTC_CCM) += src/encauth/ccm/ccm_reset.c

cppflags-lib-$(_CFG_CORE_LTC_GCM) += -DLTC_GCM_MODE
srcs-$(_CFG_CORE_LTC_GCM) += gcm.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_add_aad.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_add_iv.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_done.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_gf_mult.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_init.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_memory.c
ifeq ($(_CFG_CORE_LTC_CE),y)
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_mult_h_arm_ce.c
else
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_mult_h.c
endif
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_process.c
srcs-$(_CFG_CORE_LTC_GCM) += src/encauth/gcm/gcm_reset.c

srcs-$(_CFG_CORE_LTC_HASH) += hash.c
srcs-$(_CFG_CORE_LTC_HASH) += src/hashes/helper/hash_memory.c
srcs-$(_CFG_CORE_LTC_HASH) += src/hashes/helper/hash_memory_multi.c

cppflags-lib-$(_CFG_CORE_LTC_MD5_DESC) += -DLTC_MD5
srcs-$(_CFG_CORE_LTC_MD5_DESC) += src/hashes/md5.c

cppflags-lib-$(_CFG_CORE_LTC_SHA1_DESC) += -DLTC_SHA1
ifeq ($(_CFG_CORE_LTC_SHA1_ACCEL),y)
srcs-$(_CFG_CORE_LTC_SHA1_DESC) += sha1_accel.c
else
srcs-$(_CFG_CORE_LTC_SHA1_DESC) += src/hashes/sha1.c
endif

cppflags-lib-$(_CFG_CORE_LTC_SHA3_DESC) += -DLTC_SHA3
ifeq ($(_CFG_CORE_LTC_SHA3_ACCEL),y)
srcs-$(_CFG_CORE_LTC_SHA3_DESC) += sha3_accel.c
else
srcs-$(_CFG_CORE_LTC_SHA3_DESC) += src/hashes/sha3.c
endif
srcs-$(_CFG_CORE_LTC_SHA3_DESC) += src/hashes/sha3_test.c
srcs-$(_CFG_CORE_LTC_SHA3_DESC) += shake.c

cppflags-lib-$(_CFG_CORE_LTC_SHA224_DESC) += -DLTC_SHA224
srcs-$(_CFG_CORE_LTC_SHA224_DESC) += src/hashes/sha2/sha224.c

cppflags-lib-$(_CFG_CORE_LTC_SHA256_DESC) += -DLTC_SHA256
ifeq ($(_CFG_CORE_LTC_SHA256_ACCEL),y)
srcs-$(_CFG_CORE_LTC_SHA256_DESC) += sha256_accel.c
else
srcs-$(_CFG_CORE_LTC_SHA256_DESC) += src/hashes/sha2/sha256.c
endif

cppflags-lib-$(_CFG_CORE_LTC_SHA384_DESC) += -DLTC_SHA384
srcs-$(_CFG_CORE_LTC_SHA384_DESC) += src/hashes/sha2/sha384.c

cppflags-lib-$(_CFG_CORE_LTC_SHA512_DESC) += -DLTC_SHA512
ifeq ($(_CFG_CORE_LTC_SHA512_ACCEL),y)
srcs-$(_CFG_CORE_LTC_SHA512_DESC) += sha512_accel.c
else
srcs-$(_CFG_CORE_LTC_SHA512_DESC) += src/hashes/sha2/sha512.c
endif

cppflags-lib-$(_CFG_CORE_LTC_SHA512_256) += -DLTC_SHA512_256
srcs-$(_CFG_CORE_LTC_SHA512_256) += src/hashes/sha2/sha512_256.c

cppflags-lib-$(_CFG_CORE_LTC_HMAC) += -DLTC_HMAC
srcs-$(_CFG_CORE_LTC_HMAC) += hmac.c
srcs-$(_CFG_CORE_LTC_HMAC) += src/mac/hmac/hmac_done.c
srcs-$(_CFG_CORE_LTC_HMAC) += src/mac/hmac/hmac_init.c
srcs-$(_CFG_CORE_LTC_HMAC) += src/mac/hmac/hmac_memory.c
srcs-$(_CFG_CORE_LTC_HMAC) += src/mac/hmac/hmac_memory_multi.c
srcs-$(_CFG_CORE_LTC_HMAC) += src/mac/hmac/hmac_process.c

cppflags-lib-$(_CFG_CORE_LTC_CMAC) += -DLTC_OMAC
srcs-$(_CFG_CORE_LTC_CMAC) += cmac.c
srcs-$(_CFG_CORE_LTC_CMAC) += src/mac/omac/omac_done.c
srcs-$(_CFG_CORE_LTC_CMAC) += src/mac/omac/omac_init.c
srcs-$(_CFG_CORE_LTC_CMAC) += src/mac/omac/omac_memory.c
srcs-$(_CFG_CORE_LTC_CMAC) += src/mac/omac/omac_memory_multi.c
srcs-$(_CFG_CORE_LTC_CMAC) += src/mac/omac/omac_process.c

srcs-$(_CFG_CORE_LTC_ACIPHER) += src/math/multi.c
srcs-$(_CFG_CORE_LTC_ACIPHER) += src/math/rand_prime.c
srcs-$(_CFG_CORE_LTC_ACIPHER) += src/math/rand_bn.c
ifeq ($(_CFG_CORE_LTC_ECC),y)
srcs-$(_CFG_CORE_LTC_ACIPHER) += src/math/fp/ltc_ecc_fp_mulmod.c
endif


cppflags-lib-$(_CFG_CORE_LTC_CBC) += -DLTC_CBC_MODE
srcs-$(_CFG_CORE_LTC_CBC) += cbc.c
srcs-$(_CFG_CORE_LTC_CBC) += src/modes/cbc/cbc_decrypt.c
srcs-$(_CFG_CORE_LTC_CBC) += src/modes/cbc/cbc_done.c
srcs-$(_CFG_CORE_LTC_CBC) += src/modes/cbc/cbc_encrypt.c
srcs-$(_CFG_CORE_LTC_CBC) += src/modes/cbc/cbc_getiv.c
srcs-$(_CFG_CORE_LTC_CBC) += src/modes/cbc/cbc_setiv.c
srcs-$(_CFG_CORE_LTC_CBC) += src/modes/cbc/cbc_start.c

cppflags-lib-$(_CFG_CORE_LTC_CTR) += -DLTC_CTR_MODE
srcs-$(_CFG_CORE_LTC_CTR) += ctr.c
srcs-$(_CFG_CORE_LTC_CTR) += src/modes/ctr/ctr_decrypt.c
srcs-$(_CFG_CORE_LTC_CTR) += src/modes/ctr/ctr_done.c
srcs-$(_CFG_CORE_LTC_CTR) += src/modes/ctr/ctr_encrypt.c
srcs-$(_CFG_CORE_LTC_CTR) += src/modes/ctr/ctr_getiv.c
srcs-$(_CFG_CORE_LTC_CTR) += src/modes/ctr/ctr_setiv.c
srcs-$(_CFG_CORE_LTC_CTR) += src/modes/ctr/ctr_start.c

cppflags-lib-$(_CFG_CORE_LTC_ECB) += -DLTC_ECB_MODE
srcs-$(_CFG_CORE_LTC_ECB) += ecb.c
srcs-$(_CFG_CORE_LTC_ECB) += src/modes/ecb/ecb_decrypt.c
srcs-$(_CFG_CORE_LTC_ECB) += src/modes/ecb/ecb_done.c
srcs-$(_CFG_CORE_LTC_ECB) += src/modes/ecb/ecb_encrypt.c
srcs-$(_CFG_CORE_LTC_ECB) += src/modes/ecb/ecb_start.c

cppflags-lib-$(_CFG_CORE_LTC_XTS) += -DLTC_XTS_MODE
srcs-$(_CFG_CORE_LTC_XTS) += xts.c
srcs-$(_CFG_CORE_LTC_XTS) += src/modes/xts/xts_decrypt.c
srcs-$(_CFG_CORE_LTC_XTS) += src/modes/xts/xts_done.c
srcs-$(_CFG_CORE_LTC_XTS) += src/modes/xts/xts_encrypt.c
srcs-$(_CFG_CORE_LTC_XTS) += src/modes/xts/xts_init.c
srcs-$(_CFG_CORE_LTC_XTS) += src/modes/xts/xts_mult_x.c

srcs-$(_CFG_CORE_LTC_ACIPHER) += mpi_desc.c
cflags-mpi_desc.c-y += -Wno-declaration-after-statement
cppflags-mpi_desc.c-y += -DMBEDTLS_ALLOW_PRIVATE_ACCESS

ifeq ($(_CFG_CORE_LTC_ASN1),y)
srcs-y += src/pk/asn1/der/bit/der_decode_bit_string.c
srcs-y += src/pk/asn1/der/bit/der_encode_bit_string.c
srcs-y += src/pk/asn1/der/bit/der_length_bit_string.c
srcs-y += src/pk/asn1/der/bit/der_decode_raw_bit_string.c
srcs-y += src/pk/asn1/der/bit/der_encode_raw_bit_string.c
srcs-y += src/pk/asn1/der/boolean/der_decode_boolean.c
srcs-y += src/pk/asn1/der/boolean/der_encode_boolean.c
srcs-y += src/pk/asn1/der/boolean/der_length_boolean.c
srcs-y += src/pk/asn1/der/choice/der_decode_choice.c
srcs-y += src/pk/asn1/der/custom_type/der_decode_custom_type.c
srcs-y += src/pk/asn1/der/custom_type/der_encode_custom_type.c
srcs-y += src/pk/asn1/der/custom_type/der_length_custom_type.c
srcs-y += src/pk/asn1/der/general/der_asn1_maps.c
srcs-y += src/pk/asn1/der/general/der_decode_asn1_length.c
srcs-y += src/pk/asn1/der/general/der_decode_asn1_identifier.c
srcs-y += src/pk/asn1/der/general/der_encode_asn1_identifier.c
srcs-y += src/pk/asn1/der/general/der_encode_asn1_length.c
srcs-y += src/pk/asn1/der/general/der_length_asn1_identifier.c
srcs-y += src/pk/asn1/der/general/der_length_asn1_length.c
srcs-y += src/pk/asn1/der/generalizedtime/der_encode_generalizedtime.c
srcs-y += src/pk/asn1/der/generalizedtime/der_decode_generalizedtime.c
srcs-y += src/pk/asn1/der/generalizedtime/der_length_generalizedtime.c
srcs-y += src/pk/asn1/der/ia5/der_decode_ia5_string.c
srcs-y += src/pk/asn1/der/ia5/der_encode_ia5_string.c
srcs-y += src/pk/asn1/der/ia5/der_length_ia5_string.c
srcs-y += src/pk/asn1/der/integer/der_decode_integer.c
srcs-y += src/pk/asn1/der/integer/der_encode_integer.c
srcs-y += src/pk/asn1/der/integer/der_length_integer.c
srcs-y += src/pk/asn1/der/object_identifier/der_decode_object_identifier.c
srcs-y += src/pk/asn1/der/object_identifier/der_encode_object_identifier.c
srcs-y += src/pk/asn1/der/object_identifier/der_length_object_identifier.c
srcs-y += src/pk/asn1/der/octet/der_decode_octet_string.c
srcs-y += src/pk/asn1/der/octet/der_encode_octet_string.c
srcs-y += src/pk/asn1/der/octet/der_length_octet_string.c
srcs-y += src/pk/asn1/der/printable_string/der_decode_printable_string.c
srcs-y += src/pk/asn1/der/printable_string/der_encode_printable_string.c
srcs-y += src/pk/asn1/der/printable_string/der_length_printable_string.c
srcs-y += src/pk/asn1/der/sequence/der_decode_sequence_ex.c
srcs-y += src/pk/asn1/der/sequence/der_decode_sequence_flexi.c
srcs-y += src/pk/asn1/der/sequence/der_decode_sequence_multi.c
srcs-y += src/pk/asn1/der/sequence/der_encode_sequence_ex.c
srcs-y += src/pk/asn1/der/sequence/der_encode_sequence_multi.c
srcs-y += src/pk/asn1/der/sequence/der_length_sequence.c
srcs-y += src/pk/asn1/der/sequence/der_sequence_free.c
srcs-y += src/pk/asn1/der/set/der_encode_set.c
srcs-y += src/pk/asn1/der/set/der_encode_setof.c
srcs-y += src/pk/asn1/der/short_integer/der_decode_short_integer.c
srcs-y += src/pk/asn1/der/short_integer/der_encode_short_integer.c
srcs-y += src/pk/asn1/der/short_integer/der_length_short_integer.c
srcs-y += src/pk/asn1/der/utctime/der_decode_utctime.c
srcs-y += src/pk/asn1/der/utctime/der_encode_utctime.c
srcs-y += src/pk/asn1/der/utctime/der_length_utctime.c
srcs-y += src/pk/asn1/der/utf8/der_decode_utf8_string.c
srcs-y += src/pk/asn1/der/utf8/der_encode_utf8_string.c
srcs-y += src/pk/asn1/der/utf8/der_length_utf8_string.c
srcs-y += src/pk/asn1/der/teletex_string/der_decode_teletex_string.c
srcs-y += src/pk/asn1/der/teletex_string/der_length_teletex_string.c
srcs-y += src/pk/asn1/oid/pk_oid_cmp.c
srcs-y += src/pk/asn1/oid/pk_oid_str.c
endif

cppflags-lib-$(_CFG_CORE_LTC_DSA) += -DLTC_MDSA
srcs-$(_CFG_CORE_LTC_DSA) += dsa.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_decrypt_key.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_encrypt_key.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_export.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_free.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_generate_key.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_generate_pqg.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_import.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_make_key.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_shared_secret.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_sign_hash.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_verify_hash.c
srcs-$(_CFG_CORE_LTC_DSA) += src/pk/dsa/dsa_verify_key.c

cppflags-lib-$(_CFG_CORE_LTC_RSA) += -DLTC_MRSA
srcs-$(_CFG_CORE_LTC_RSA) += rsa.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_i2osp.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_mgf1.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_oaep_decode.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_oaep_encode.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_os2ip.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_pss_decode.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_pss_encode.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_v1_5_decode.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/pkcs1/pkcs_1_v1_5_encode.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_decrypt_key.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_encrypt_key.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_export.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_exptmod.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_import.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_key.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_make_key.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_sign_hash.c
srcs-$(_CFG_CORE_LTC_RSA) += src/pk/rsa/rsa_verify_hash.c

cppflags-lib-$(_CFG_CORE_LTC_DH) += -DLTC_MDH
srcs-$(_CFG_CORE_LTC_DH) += dh.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_check_pubkey.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_export.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_export_key.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_free.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_generate_key.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_import.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_make_key.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_set.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_set_pg_dhparam.c
srcs-$(_CFG_CORE_LTC_DH) += src/pk/dh/dh_shared_secret.c

cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_MECC
# use Shamir's trick for point mul (speeds up signature verification)
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_ECC_SHAMIR
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_ECC192
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_ECC224
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_ECC256
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_ECC384
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_ECC521
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_CURVE25519
# ECC 521 bits is the max supported key size
cppflags-lib-$(_CFG_CORE_LTC_ECC) += -DLTC_MAX_ECC=521
srcs-$(_CFG_CORE_LTC_ECC) += ecc.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_find_curve.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_free.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_get_oid_str.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_make_key.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_set_curve.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_set_curve_internal.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_shared_secret.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_sign_hash.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_ssh_ecdsa_encode_name.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ecc_verify_hash.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_is_point.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_is_point_at_infinity.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_map.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_mulmod.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_mulmod_timing.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_mul2add.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_points.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_projective_add_point.c
srcs-$(_CFG_CORE_LTC_ECC) += src/pk/ecc/ltc_ecc_projective_dbl_point.c

ifneq (,$(filter y,$(_CFG_CORE_LTC_SM2_DSA) $(_CFG_CORE_LTC_SM2_PKE)))
   cppflags-lib-y += -DLTC_ECC_SM2
endif
srcs-$(_CFG_CORE_LTC_SM2_DSA) += sm2-dsa.c
srcs-$(_CFG_CORE_LTC_SM2_PKE) += sm2-pke.c
srcs-$(_CFG_CORE_LTC_SM2_KEP) += sm2-kep.c

cppflags-lib-$(_CFG_CORE_LTC_EC25519) += -DLTC_CURVE25519
srcs-$(_CFG_CORE_LTC_EC25519) += src/pk/ec25519/ec25519_crypto_ctx.c
srcs-$(_CFG_CORE_LTC_EC25519) += src/pk/ec25519/ec25519_export.c
srcs-$(_CFG_CORE_LTC_EC25519) += src/pk/ec25519/tweetnacl.c

srcs-$(_CFG_CORE_LTC_ED25519) += ed25519.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_export.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_import.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_import_pkcs8.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_import_x509.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_make_key.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_sign.c
srcs-$(_CFG_CORE_LTC_ED25519) += src/pk/ed25519/ed25519_verify.c

srcs-$(_CFG_CORE_LTC_X25519) += x25519.c
cflags-x25519.c-y += -Wno-declaration-after-statement
srcs-$(_CFG_CORE_LTC_X25519) += src/pk/x25519/x25519_export.c
srcs-$(_CFG_CORE_LTC_X25519) += src/pk/x25519/x25519_import.c
srcs-$(_CFG_CORE_LTC_X25519) += src/pk/x25519/x25519_make_key.c
srcs-$(_CFG_CORE_LTC_X25519) += src/pk/x25519/x25519_shared_secret.c
