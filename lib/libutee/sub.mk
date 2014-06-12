global-incdirs-y += include

srcs-y += tee_api_property.c
cflags-tee_api_property.c-y += -Wno-redundant-decls

srcs-y += tee_user_mem.c
cflags-remove-tee_user_mem.c-y += -Wdeclaration-after-statement

srcs-y += abort.c
cflags-abort.c-y += -Wno-missing-prototypes -Wno-missing-declarations
cflags-abort.c-y += -Wno-error

srcs-y += ta_trace.c
cflags-ta_trace.c-y += -Wno-redundant-decls

srcs-y += assert.c
cflags-assert.c-y += -Wno-missing-prototypes -Wno-missing-declarations

srcs-y += base64.c
srcs-y += tee_api_arith.c
srcs-y += tee_api.c
srcs-y += tee_api_objects.c
srcs-y += tee_api_operations.c

subdirs-y += arch/$(ARCH)
