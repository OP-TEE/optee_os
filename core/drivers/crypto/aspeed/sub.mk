ifeq ($(PLATFORM_FLAVOR),ast2600)
srcs-y += crypto_ast2600.c
srcs-$(CFG_CRYPTO_DRV_HASH) += hace_ast2600.c
endif
