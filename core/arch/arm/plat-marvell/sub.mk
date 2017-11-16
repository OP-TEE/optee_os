global-incdirs-y += .
srcs-y += main.c
srcs-$(PLATFORM_FLAVOR_armada7k8k) += armada7k8k/hal_sec_perf.c
srcs-$(PLATFORM_FLAVOR_armada3700) += armada3700/hal_sec_perf.c
