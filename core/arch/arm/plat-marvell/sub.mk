global-incdirs-y += .
srcs-y += main.c
ifeq ($(PLATFORM_FLAVOR_armada7k8k),y)
srcs-y += armada7k8k/hal_sec_perf.c
endif
