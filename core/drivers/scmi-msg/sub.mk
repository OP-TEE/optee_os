srcs-y += base.c
srcs-$(CFG_SCMI_MSG_CLOCK) += clock.c
srcs-y += entry.c
srcs-$(CFG_SCMI_MSG_RESET_DOMAIN) += reset_domain.c
srcs-$(CFG_SCMI_MSG_SMT) += smt.c
srcs-$(CFG_SCMI_MSG_VOLTAGE_DOMAIN) += voltage_domain.c
