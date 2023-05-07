global-incdirs-y += .
srcs-y += main.c
srcs-$(CFG_WITH_USER_TA) += vendor_props.c
subdirs-y += utils