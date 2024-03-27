incdirs-y += include

srcs-y += hisi_qm.c
srcs-y += sec_main.c
srcs-$(CFG_HISILICON_ACC_V3) += hpre_main.c
srcs-$(CFG_HISILICON_ACC_V3) += hpre_dh.c
