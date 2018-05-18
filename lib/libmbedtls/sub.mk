global-incdirs-y += include
global-incdirs-y += mbedtls/include

SRCS :=

# OBJS_CRYPTO from make file
SRCS += aes.c
SRCS += aesni.c
SRCS += arc4.c
SRCS += asn1parse.c
SRCS += asn1write.c
SRCS += base64.c
SRCS += bignum.c
SRCS += blowfish.c
SRCS += camellia.c
SRCS += ccm.c
SRCS += cipher.c
SRCS += cipher_wrap.c
SRCS += cmac.c
SRCS += ctr_drbg.c
SRCS += des.c
SRCS += dhm.c
SRCS += ecdh.c
SRCS += ecdsa.c
SRCS += ecjpake.c
SRCS += ecp.c
SRCS += ecp_curves.c
SRCS += entropy.c
SRCS += entropy_poll.c
SRCS += error.c
SRCS += gcm.c
SRCS += havege.c
SRCS += hmac_drbg.c
SRCS += md.c
SRCS += md2.c
SRCS += md4.c
SRCS += md5.c
SRCS += md_wrap.c
SRCS += memory_buffer_alloc.c
SRCS += oid.c
SRCS += padlock.c
SRCS += pem.c
SRCS += pk.c
SRCS += pk_wrap.c
SRCS += pkcs12.c
SRCS += pkcs5.c
SRCS += pkparse.c
SRCS += pkwrite.c
SRCS += platform.c
SRCS += ripemd160.c
SRCS += rsa.c
SRCS += sha1.c
SRCS += sha256.c
SRCS += sha512.c
SRCS += threading.c
SRCS += timing.c
SRCS += version.c
SRCS += version_features.c
SRCS += xtea.c

# OBJS_X509
SRCS += certs.c
SRCS += pkcs11.c
SRCS += x509.c
SRCS += x509_create.c
SRCS += x509_crl.c
SRCS += x509_crt.c
SRCS += x509_csr.c
SRCS += x509write_crt.c
SRCS += x509write_csr.c

# OBJS_TLS
SRCS += debug.c
SRCS += net_sockets.c
SRCS += ssl_cache.c
SRCS += ssl_ciphersuites.c
SRCS += ssl_cli.c
SRCS += ssl_cookie.c
SRCS += ssl_srv.c
SRCS += ssl_ticket.c
SRCS += ssl_tls.c

srcs-y += $(addprefix mbedtls/library/, $(SRCS))

cflags-lib-y += -Wno-redundant-decls
cflags-lib-y += -Wno-switch-default
cflags-lib-$(CFG_ULIBS_GPROF) += -pg
