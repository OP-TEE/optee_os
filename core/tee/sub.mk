srcs-y += tee_svc.c
srcs-y += tee_svc_cryp.c
srcs-y += tee_acipher.c
cflags-tee_acipher.c-y += -Wno-unused-parameter

srcs-y += tee_authenc.c
cflags-tee_authenc.c-y += -Wno-unused-parameter

srcs-y += tee_mac.c
cflags-tee_mac.c-y += -Wno-unused-parameter

srcs-y += tee_cipher.c
srcs-y += tee_fs.c
srcs-y += tee_hash.c
srcs-y += tee_obj.c
srcs-y += tee_pobj.c
srcs-y += tee_rpmb_fs.c
srcs-y += tee_svc_storage.c
srcs-y += tee_time_generic.c
