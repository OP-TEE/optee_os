srcs-y += hisi_qm.c
srcs-y += sec_main.c
srcs-y += sec_hash.c
srcs-y += sec_hmac.c
srcs-y += sec_cipher.c
srcs-$(CFG_HISILICON_ACC_V3) += hpre_main.c
srcs-$(CFG_HISILICON_ACC_V3) += hpre_dh.c
srcs-$(CFG_HISILICON_ACC_V3) += hpre_ecc.c
