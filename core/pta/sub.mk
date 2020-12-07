subdirs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += tests

srcs-$(CFG_TEE_BENCHMARK) += benchmark.c
srcs-$(CFG_DEVICE_ENUM_PTA) += device.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
srcs-$(CFG_SDP_PTA) += sdp.c
ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_SECSTOR_TA_MGMT_PTA) += secstor_ta_mgmt.c
endif
srcs-$(CFG_WITH_STATS) += stats.c
srcs-$(CFG_SYSTEM_PTA) += system.c
srcs-$(CFG_NXP_SE05X) += scp03.c
srcs-$(CFG_DEFERRED_WORK) += dw.c

subdirs-y += bcm
