incdirs-y += include

srcs-y += ele.c
srcs-y += memutils.c
srcs-$(CFG_IMX_ELE_ECC_DRV) += key_mgmt.c
srcs-$(CFG_IMX_ELE_ECC_DRV) += sign_verify.c
subdirs-$(CFG_IMX_ELE_ECC_DRV) += acipher
