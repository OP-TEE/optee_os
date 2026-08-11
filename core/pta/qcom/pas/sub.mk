srcs-y += pta_qcom_pas.c
srcs-y += pas_core.c
srcs-$(CFG_QCOM_PAS_AUTH) += pas_auth_core.c
incdirs-y += .
incdirs-y += platform/
subdirs-y += platform/$(PLATFORM_FLAVOR)

# PIL PAS authentication metadata slots, defaults to 1.
CFG_PAS_MD_SLOTS ?= 1
