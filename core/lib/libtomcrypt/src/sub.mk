subdirs-$(_CFG_CRYPTO_WITH_CIPHER) += ciphers
subdirs-$(_CFG_CRYPTO_WITH_AUTHENC) += encauth
subdirs-y += hashes
subdirs-$(_CFG_CRYPTO_WITH_MAC) += mac
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += math
subdirs-y += misc
subdirs-y += modes
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += pk
