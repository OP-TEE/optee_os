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
ifeq ($(CFG_TEE_PANIC_DEBUG_ADDR),)
srcs-y += tee_api_panic.c
else
srcs-$(CFG_ARM32_$(sm)) += tee_api_panic_a32.S
srcs-$(CFG_ARM64_$(sm)) += tee_api_panic_a64.S
endif
srcs-y += tee_tcpudp_socket.c
srcs-y += tee_socket_pta.c

subdirs-y += tui
subdirs-y += arch/$(ARCH)

cflags-lib-$(CFG_ULIBS_GPROF) += -pg
