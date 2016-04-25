ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_ARM32_core) += arch_svc_a32.S
srcs-$(CFG_ARM64_core) += arch_svc_a64.S
srcs-$(CFG_CACHE_API) += svc_cache.c
srcs-y += arch_svc.c
else
srcs-y += svc_dummy.c
endif
srcs-y += entry_std.c
srcs-y += entry_fast.c
srcs-y += init.c
