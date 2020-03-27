incdirs-y += ../include

srcs-y += utils_mem.c
srcs-y += utils_delay.c
srcs-y += utils_sgt.c
srcs-$(CFG_NXP_CAAM_SGT_V1) += utils_sgt_v1.c
srcs-$(CFG_NXP_CAAM_SGT_V2) += utils_sgt_v2.c
srcs-y += utils_status.c
srcs-y += utils_dmaobj.c
