global-incdirs-y += .
srcs-y += main.c
ifneq (,$(filter $(PLATFORM_FLAVOR),otx2t96 otx2f95 otx2t98))
srcs-$(CFG_ARM64_core) += otx2/core_pos.S
endif
ifneq (,$(filter $(PLATFORM_FLAVOR),cn10ka cn10kb cnf10ka cnf10kb))
srcs-$(CFG_ARM64_core) += cn10k/core_pos.S
endif
srcs-$(PLATFORM_FLAVOR_armada7k8k) += armada7k8k/hal_sec_perf.c
srcs-$(PLATFORM_FLAVOR_armada3700) += armada3700/hal_sec_perf.c
