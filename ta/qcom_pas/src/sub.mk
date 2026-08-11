global-incdirs-y += ../include
srcs-y += qcom_pas.c
srcs-$(CFG_QCOM_PAS_AUTH) += auth/pas_mbn.c
