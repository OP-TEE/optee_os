srcs-$(_CFG_CORE_LTC_SHA224) += sha224.c

ifeq ($(_CFG_CORE_LTC_SHA256_DESC),y)
SHA256_CE := $(call cfg-one-enabled, _CFG_CORE_LTC_SHA256_ARM32_CE \
				     _CFG_CORE_LTC_SHA256_ARM64_CE)
ifeq ($(SHA256_CE),y)
srcs-y += sha256_armv8a_ce.c
srcs-$(_CFG_CORE_LTC_SHA256_ARM32_CE) += sha256_armv8a_ce_a32.S
srcs-$(_CFG_CORE_LTC_SHA256_ARM64_CE) += sha256_armv8a_ce_a64.S
else
srcs-y += sha256.c
endif
endif

srcs-$(_CFG_CORE_LTC_SHA384_DESC) += sha384.c
srcs-$(_CFG_CORE_LTC_SHA512_DESC) += sha512.c
srcs-$(_CFG_CORE_LTC_SHA512_256) += sha512_256.c
