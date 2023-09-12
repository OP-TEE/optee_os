global-incdirs-y += .
srcs-y += freq.c sam_sfr.c
srcs-$(CFG_SAMA5D2) += platform_sama5d2.c
srcs-$(CFG_SAMA7G5) += platform_sama7g5.c
srcs-$(CFG_AT91_MATRIX) += matrix.c
srcs-$(CFG_PL310) += sam_pl310.c
srcs-$(CFG_SCMI_MSG_DRIVERS) += scmi_server.c

subdirs-y += pm
subdirs-y += nsec-service
