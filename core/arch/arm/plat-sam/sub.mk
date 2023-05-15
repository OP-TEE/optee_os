global-incdirs-y += .
srcs-y += main.c freq.c sam_sfr.c
srcs-$(CFG_AT91_MATRIX) += matrix.c
srcs-$(CFG_PL310) += sam_pl310.c
subdirs-y += pm
subdirs-y += nsec-service
