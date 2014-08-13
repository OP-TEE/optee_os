srcs-y += arch_tee_fs.c
srcs-y += tee_rpmb.c
cflags-tee_rpmb.c-y += -Wno-unused-parameter
srcs-y += tee_svc_asm.S
srcs-y += entry.c
srcs-y += init.c
cflags-init.c-y += -Wno-unused-parameter
