cppflags-y += -I$(sub-dir)/../../..

srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof_pta.c
cflags-remove-gprof.c-y += -Wcast-align
