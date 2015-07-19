subdirs-$(_CFG_CRYPTO_WITH_ASN1) += asn1
subdirs-$(CFG_CRYPTO_DSA) += dsa
# PKCS1 paddings are used with RSA only
subdirs-$(CFG_CRYPTO_RSA) += pkcs1
subdirs-$(CFG_CRYPTO_RSA) += rsa
subdirs-$(CFG_CRYPTO_DH) += dh
subdirs-$(CFG_CRYPTO_ECC) += ecc
