global-incdirs-y += include

srcs-y += tee_api_property.c
srcs-y += tee_user_mem.c
srcs-y += abort.c
srcs-y += trace_ext.c
srcs-y += assert.c
srcs-y += base64.c
srcs-y += tee_api_arith.c
srcs-y += tee_api.c
srcs-y += tee_api_objects.c
srcs-y += tee_api_operations.c
srcs-y += tee_api_se.c

subdirs-y += arch/$(ARCH)

ifeq ($(CFG_PLATFORM_SPECIFIC_PROPERTIES),y)
global-incdirs-y += arch/$(ARCH)/plat-$(PLATFORM)
srcs-y += arch/$(ARCH)/plat-$(PLATFORM)/platform_properties.c
endif
