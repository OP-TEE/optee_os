srcs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += sta_self_tests.c
srcs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += core_self_tests.c
srcs-$(CFG_WITH_STATS) += stats.c

ifeq ($(CFG_SE_API),y)
srcs-$(CFG_SE_API_SELF_TEST) += se_api_self_tests.c
cppflags-se_api_self_tests.c-y += -Icore/tee/se
endif

ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_TEE_FS_KEY_MANAGER_TEST) += tee_fs_key_manager_tests.c
endif
