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
srcs-y += tee_api_panic.c

subdirs-y += tui
subdirs-y += arch/$(ARCH)
