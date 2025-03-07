global-incdirs-y += .

srcs-y += main.c
srcs-y += reset.S
srcs-$(CFG_SCMI_MSG_DRIVERS) += scmi_server.c
srcs-$(CFG_TZC400) += plat_tzc400.c
srcs-$(CFG_WITH_PAGER) += link_dummies_paged.c

subdirs-y += drivers
subdirs-y += nsec-service
subdirs-y += pm
