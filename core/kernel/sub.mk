srcs-y += assert.c
srcs-y += tee_dispatch.c
srcs-y += tee_ta_manager.c
srcs-y += tee_misc.c
srcs-y += panic.c
srcs-y += handle.c
srcs-y += interrupt.c
srcs-$(CFG_CORE_SANITIZE_UNDEFINED) += ubsan.c
