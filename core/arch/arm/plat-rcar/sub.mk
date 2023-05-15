global-incdirs-y += .
srcs-y += main.c
srcs-${CFG_RCAR_GEN3} += core_pos_a64.S
srcs-${CFG_RCAR_ROMAPI} += romapi.c
srcs-${CFG_RCAR_ROMAPI} += romapi_call.S
srcs-${CFG_RCAR_ROMAPI} += hw_rng.c
