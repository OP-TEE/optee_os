srcs-$(CFG_VERAISON_ATTESTATION_PTA) += veraison_attestation.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += cbor.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += hash.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += key.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += sign.c
ifeq ($(CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS),y)
srcs-$(CFG_MX8M) += platform_imx8m.c
endif

cflags-$(CFG_VERAISON_ATTESTATION_PTA) += -Wno-declaration-after-statement
cflags-$(CFG_VERAISON_ATTESTATION_PTA) += -Wno-redundant-decls
