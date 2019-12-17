srcs-y += base.c
srcs-$(CFG_SCMI_MSG_CLOCK) += clock.c
srcs-y += entry.c
srcs-$(CFG_ARM32_core) += platform_weaks_a32.S
srcs-$(CFG_ARM64_core) += platform_weaks_a64.S
srcs-$(CFG_SCMI_MSG_RESET_DOMAIN) += reset_domain.c
srcs-$(CFG_SCMI_MSG_SMT) += smt.c
