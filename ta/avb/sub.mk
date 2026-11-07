# CFG_AVB_TA_DEFAULT_LOCKED, when enabled, reports the device as locked until
# its lock state is first written, for products that must not start out unlocked.
CFG_AVB_TA_DEFAULT_LOCKED ?= n

global-incdirs-y += include
global-incdirs-y += .
srcs-y += entry.c
