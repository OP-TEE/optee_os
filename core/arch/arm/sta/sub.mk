srcs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += sta_self_tests.c
srcs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += core_self_tests.c

srcs-$(CFG_SE_API_SELF_TEST) += se_api_self_tests.c
cppflags-se_api_self_tests.c-y += -Icore/tee/se

srcs-$(CFG_ENC_FS_KEY_MANAGER_TEST) += enc_fs_key_manager_tests.c
