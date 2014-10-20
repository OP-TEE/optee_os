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

subdirs-y += arch/$(ARCH)
