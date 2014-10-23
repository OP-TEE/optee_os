incdirs-y := .. ../.. ../../include

cflags-remove-y := -Wcast-align -Wswitch-default

srcs-y += a_bitstr.c
srcs-y += a_int.c
srcs-y += a_object.c
srcs-y += a_type.c
srcs-y += ameth_lib.c
srcs-y += asn1_lib.c
srcs-y += evp_asn1.c
srcs-y += tasn_dec.c
srcs-y += tasn_enc.c
srcs-y += tasn_fre.c
srcs-y += tasn_new.c
srcs-y += tasn_typ.c
srcs-y += tasn_utl.c
srcs-y += x_algor.c
srcs-y += x_attrib.c
srcs-y += x_sig.c
