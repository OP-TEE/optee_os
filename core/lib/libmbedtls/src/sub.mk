srcs-y += tee_lmd_provider.c

# For mbedtls
cflags-y += -Icore/lib/libmbedtls/src/mbedtls/include
cppflags-y += -D'MBEDTLS_CONFIG_FILE="mbedtls_config.h"'

# Hashes
srcs-y += mbedtls/library/md5.c \
		mbedtls/library/sha1.c \
		mbedtls/library/sha256.c \
		mbedtls/library/sha512.c
