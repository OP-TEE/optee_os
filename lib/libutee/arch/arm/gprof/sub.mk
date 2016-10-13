cppflags-y += -I$(sub-dir)/../../..

srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof_pta.c
cflags-remove-gprof.c-y += -Wcast-align
srcs-$(CFG_ARM32_$(sm)) += gprof_a32.S
srcs-$(CFG_ARM64_$(sm)) += gprof_a64.S
