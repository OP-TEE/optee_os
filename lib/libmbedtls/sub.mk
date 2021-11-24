global-incdirs-y += include
global-incdirs-y += mbedtls/include

# OBJS_CRYPTO from make file
SRCS_CRYPTO :=
ifneq ($(sm),core)
SRCS_CRYPTO += aes.c
SRCS_CRYPTO += aesni.c
SRCS_CRYPTO += arc4.c
SRCS_CRYPTO += aria.c
SRCS_CRYPTO += asn1parse.c
SRCS_CRYPTO += asn1write.c
SRCS_CRYPTO += base64.c
SRCS_CRYPTO += bignum.c
SRCS_CRYPTO += blowfish.c
SRCS_CRYPTO += camellia.c
SRCS_CRYPTO += ccm.c
SRCS_CRYPTO += chacha20.c
SRCS_CRYPTO += chachapoly.c
SRCS_CRYPTO += cipher.c
SRCS_CRYPTO += cipher_wrap.c
SRCS_CRYPTO += cmac.c
SRCS_CRYPTO += ctr_drbg.c
SRCS_CRYPTO += des.c
SRCS_CRYPTO += dhm.c
SRCS_CRYPTO += ecdh.c
SRCS_CRYPTO += ecdsa.c
SRCS_CRYPTO += ecjpake.c
SRCS_CRYPTO += ecp.c
SRCS_CRYPTO += ecp_curves.c
SRCS_CRYPTO += entropy.c
SRCS_CRYPTO += entropy_poll.c
SRCS_CRYPTO += error.c
SRCS_CRYPTO += gcm.c
SRCS_CRYPTO += havege.c
SRCS_CRYPTO += hkdf.c
SRCS_CRYPTO += hmac_drbg.c
SRCS_CRYPTO += md.c
SRCS_CRYPTO += md2.c
SRCS_CRYPTO += md4.c
SRCS_CRYPTO += md5.c
SRCS_CRYPTO += memory_buffer_alloc.c
SRCS_CRYPTO += nist_kw.c
SRCS_CRYPTO += oid.c
SRCS_CRYPTO += padlock.c
SRCS_CRYPTO += pem.c
SRCS_CRYPTO += pk.c
SRCS_CRYPTO += pk_wrap.c
SRCS_CRYPTO += pkcs12.c
SRCS_CRYPTO += pkcs5.c
SRCS_CRYPTO += pkparse.c
SRCS_CRYPTO += pkwrite.c
SRCS_CRYPTO += platform.c
SRCS_CRYPTO += platform_util.c
SRCS_CRYPTO += poly1305.c
SRCS_CRYPTO += ripemd160.c
SRCS_CRYPTO += rsa_internal.c
SRCS_CRYPTO += rsa.c
SRCS_CRYPTO += sha1.c
SRCS_CRYPTO += sha256.c
SRCS_CRYPTO += sha512.c
SRCS_CRYPTO += threading.c
SRCS_CRYPTO += timing.c
SRCS_CRYPTO += version.c
SRCS_CRYPTO += version_features.c
SRCS_CRYPTO += xtea.c
else
SRCS_CRYPTO += aes.c
SRCS_CRYPTO += aesni.c
SRCS_CRYPTO += asn1parse.c
SRCS_CRYPTO += asn1write.c
SRCS_CRYPTO += bignum.c
SRCS_CRYPTO += cipher.c
SRCS_CRYPTO += cipher_wrap.c
SRCS_CRYPTO += cmac.c
SRCS_CRYPTO += ctr_drbg.c
SRCS_CRYPTO += des.c
SRCS_CRYPTO += dhm.c
SRCS_CRYPTO += ecdh.c
SRCS_CRYPTO += ecdsa.c
SRCS_CRYPTO += ecp.c
SRCS_CRYPTO += ecp_curves.c
SRCS_CRYPTO += md.c
SRCS_CRYPTO += md5.c
SRCS_CRYPTO += oid.c
SRCS_CRYPTO += pk.c
SRCS_CRYPTO += pk_wrap.c
SRCS_CRYPTO += platform.c
SRCS_CRYPTO += platform_util.c
SRCS_CRYPTO += rsa_internal.c
SRCS_CRYPTO += rsa.c
SRCS_CRYPTO += sha1.c
SRCS_CRYPTO += sha256.c
SRCS_CRYPTO += sha512.c
endif

# OBJS_X509
SRCS_X509 :=
SRCS_X509 += certs.c
SRCS_X509 += pkcs11.c
SRCS_X509 += x509.c
SRCS_X509 += x509_create.c
SRCS_X509 += x509_crl.c
SRCS_X509 += x509_crt.c
SRCS_X509 += x509_csr.c
SRCS_X509 += x509write_crt.c
SRCS_X509 += x509write_csr.c

# OBJS_TLS
SRCS_TLS :=
SRCS_TLS += debug.c
SRCS_TLS += net_sockets.c
SRCS_TLS += ssl_cache.c
SRCS_TLS += ssl_ciphersuites.c
SRCS_TLS += ssl_cli.c
SRCS_TLS += ssl_cookie.c
SRCS_TLS += ssl_srv.c
SRCS_TLS += ssl_ticket.c
SRCS_TLS += ssl_tls.c

srcs-y += $(addprefix mbedtls/library/, $(SRCS_CRYPTO))
srcs-$(sm-$(ta-target)) += $(addprefix mbedtls/library/, $(SRCS_X509))
srcs-$(sm-$(ta-target)) += $(addprefix mbedtls/library/, $(SRCS_TLS))

cflags-lib-y += -Wno-redundant-decls
cflags-lib-y += -Wno-switch-default
cflags-lib-y += -Wno-declaration-after-statement

ifeq ($(CFG_CRYPTOLIB_NAME_mbedtls),y)
subdirs-$(sm-core) += core
endif
