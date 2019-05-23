global-incdirs-y += include

srcs-y += abort.c
srcs-y += trace_ext.c
srcs-y += assert.c
ifneq ($(sm),ldelf)
srcs-y += tee_api_property.c
srcs-y += base64.c
srcs-y += tee_api.c
srcs-y += tee_api_objects.c
srcs-y += tee_api_operations.c
srcs-y += tee_api_panic.c
srcs-y += tee_tcpudp_socket.c
srcs-y += tee_socket_pta.c
srcs-y += tee_system_pta.c


ifeq ($(CFG_TA_MBEDTLS_MPI),y)
srcs-y += tee_api_arith_mpi.c
else
srcs-y += tee_api_arith_mpa.c
endif
endif #ifneq ($(sm),ldelf)

subdirs-y += arch/$(ARCH)
