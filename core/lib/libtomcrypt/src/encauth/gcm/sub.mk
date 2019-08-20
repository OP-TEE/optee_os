srcs-y += gcm_add_aad.c
srcs-y += gcm_add_iv.c
srcs-y += gcm_done.c
srcs-y += gcm_gf_mult.c
srcs-y += gcm_init.c
srcs-y += gcm_memory.c
ifeq ($(_CFG_CORE_LTC_CE),y)
srcs-y += gcm_mult_h_arm_ce.c
else
srcs-y += gcm_mult_h.c
endif
srcs-y += gcm_process.c
srcs-y += gcm_reset.c
