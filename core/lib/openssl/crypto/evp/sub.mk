incdirs-y := .. ../.. ../../include ../asn1 ../modes

cflags-remove-y := -Wcast-align
cflags-y := -Wno-unused-parameter

srcs-y += digest.c
srcs-y += e_aes.c
srcs-y += e_des3.c
srcs-y += e_des.c
srcs-y += e_rc5.c
srcs-y += evp_enc.c
srcs-y += evp_lib.c
srcs-y += m_md5.c
srcs-y += m_sha1.c
srcs-y += m_sha.c
srcs-y += names.c
srcs-y += p_lib.c
srcs-y += pmeth_lib.c

