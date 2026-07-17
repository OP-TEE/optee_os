global-incdirs-y += ../include
srcs-y += qcom_pas.c
srcs-$(CFG_QCOM_PAS_AUTH) += pas_auth.c
srcs-$(CFG_QCOM_PAS_AUTH) += pas_mbn_parser.c
