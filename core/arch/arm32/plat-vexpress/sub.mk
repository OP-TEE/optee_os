global-incdirs-y += .
srcs-y += entry.S
srcs-y += main.c
srcs-y += tee_common_otp.c
srcs-y += core_bootcfg.c
srcs-y += core_chip.c
srcs-y += rng_support.c
srcs-$(PLATFORM_FLAVOR_juno) += juno_core_pos.S
