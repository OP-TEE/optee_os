ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_ARM32_core) += arch_svc_a32.S
srcs-$(CFG_ARM64_core) += arch_svc_a64.S
srcs-$(CFG_CACHE_API) += svc_cache.c
srcs-y += arch_svc.c
flags-arch_svc.c-y += $(call cc-option,-mtrack-speculation)
else
srcs-y += svc_dummy.c
endif
srcs-y += entry_std.c
srcs-y += entry_fast.c
cppflags-entry_fast.c-y += -DTEE_IMPL_GIT_SHA1=$(TEE_IMPL_GIT_SHA1)
srcs-y += init.c
srcs-y += cache.c
