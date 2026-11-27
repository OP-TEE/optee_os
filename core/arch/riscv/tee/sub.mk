ifneq ($(CFG_RPMI_TEE_ABI),y)
srcs-y += entry_fast.c
cppflags-entry_fast.c-y += -DTEE_IMPL_GIT_SHA1=$(TEE_IMPL_GIT_SHA1)
endif
srcs-y += cache.c
