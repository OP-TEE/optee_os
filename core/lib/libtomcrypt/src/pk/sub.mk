subdirs-$(_CFG_CORE_LTC_ASN1) += asn1
subdirs-$(_CFG_CORE_LTC_DSA) += dsa
# PKCS1 paddings are used with RSA only
subdirs-$(_CFG_CORE_LTC_RSA) += pkcs1
subdirs-$(_CFG_CORE_LTC_RSA) += rsa
subdirs-$(_CFG_CORE_LTC_DH) += dh
subdirs-$(_CFG_CORE_LTC_ECC) += ecc
subdirs-$(_CFG_CORE_LTC_X25519) += ec25519
subdirs-$(_CFG_CORE_LTC_X25519) += x25519
subdirs-$(_CFG_CORE_LTC_ED25519) += ec25519
subdirs-$(_CFG_CORE_LTC_ED25519) += ed25519
