srcs-y += arch_tee_fs.c
srcs-y += tee_rpmb.c
srcs-$(CFG_ARM32_core) += arch_svc_a32.S
srcs-$(CFG_ARM64_core) += arch_svc_a64.S
srcs-y += arch_svc.c
srcs-y += entry.c
srcs-y += init.c
