global-incdirs-y += .

srcs-y += main.c
srcs-y += reset.S
srcs-$(CFG_STM32_RNG) += rng_seed.c
srcs-$(CFG_SCMI_MSG_DRIVERS) += scmi_server.c
srcs-y += shared_resources.c
srcs-$(CFG_TZC400) += plat_tzc400.c

subdirs-y += drivers
subdirs-y += nsec-service
subdirs-y += pm
