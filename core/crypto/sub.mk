srcs-y += crypto.c
srcs-y += aes-gcm.c
srcs-y += aes-gcm-sw.c
ifeq ($(CFG_AES_GCM_TABLE_BASED),y)
srcs-y += aes-gcm-ghash-tbl.c
else
srcs-y += aes-gcm-ghash.c
endif
