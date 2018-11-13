ifeq (y,$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS))
srcs-y += pta_invoke_tests.c
srcs-y += core_self_tests.c
srcs-y += interrupt_tests.c
srcs-y += core_mutex_tests.c
srcs-$(CFG_WITH_USER_TA) += core_fs_htree_tests.c
srcs-$(CFG_LOCKDEP) += core_lockdep_tests.c
endif
ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_SECSTOR_TA_MGMT_PTA) += secstor_ta_mgmt.c
endif
srcs-$(CFG_WITH_STATS) += stats.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
srcs-$(CFG_TEE_BENCHMARK) += benchmark.c
srcs-$(CFG_SDP_PTA) += sdp_pta.c
srcs-$(CFG_SYSTEM_PTA) += system.c

ifeq ($(CFG_SE_API),y)
srcs-$(CFG_SE_API_SELF_TEST) += se_api_self_tests.c
cppflags-se_api_self_tests.c-y += -Icore/tee/se
endif
