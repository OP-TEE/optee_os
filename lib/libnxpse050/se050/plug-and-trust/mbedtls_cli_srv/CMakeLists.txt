CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

project (ssl2_client)

FILE(
    GLOB
    MBEDTLS_SOURCES
    ../ext/mbedtls/library/aes.c
    ../ext/mbedtls/library/aesni.c
    ../ext/mbedtls/library/arc4.c
    ../ext/mbedtls/library/aria.c
    ../ext/mbedtls/library/asn1parse.c
    ../ext/mbedtls/library/asn1write.c
    ../ext/mbedtls/library/base64.c
    ../ext/mbedtls/library/bignum.c
    ../ext/mbedtls/library/blowfish.c
    ../ext/mbedtls/library/camellia.c
    ../ext/mbedtls/library/ccm.c
    ../ext/mbedtls/library/certs.c
    ../ext/mbedtls/library/chacha20.c
    ../ext/mbedtls/library/chachapoly.c
    ../ext/mbedtls/library/cipher.c
    ../ext/mbedtls/library/cipher_wrap.c
    ../ext/mbedtls/library/cmac.c
    ../ext/mbedtls/library/ctr_drbg.c
    ../ext/mbedtls/library/debug.c
    ../ext/mbedtls/library/des.c
    ../ext/mbedtls/library/dhm.c
    #../ext/mbedtls/library/ecdh.c
    ../ext/mbedtls/library/ecdsa.c
    ../ext/mbedtls/library/ecjpake.c
    ../ext/mbedtls/library/ecp.c
    ../ext/mbedtls/library/ecp_curves.c
    ../ext/mbedtls/library/entropy.c
    ../ext/mbedtls/library/entropy_poll.c
    ../ext/mbedtls/library/error.c
    ../ext/mbedtls/library/gcm.c
    ../ext/mbedtls/library/havege.c
    ../ext/mbedtls/library/hkdf.c
    ../ext/mbedtls/library/hmac_drbg.c
    ../ext/mbedtls/library/md.c
    ../ext/mbedtls/library/md2.c
    ../ext/mbedtls/library/md4.c
    ../ext/mbedtls/library/md5.c
    ../ext/mbedtls/library/md_wrap.c
    ../ext/mbedtls/library/memory_buffer_alloc.c
    ../ext/mbedtls/library/net_sockets.c
    ../ext/mbedtls/library/nist_kw.c
    ../ext/mbedtls/library/oid.c
    ../ext/mbedtls/library/padlock.c
    ../ext/mbedtls/library/pem.c
    ../ext/mbedtls/library/pk.c
    ../ext/mbedtls/library/pk_wrap.c
    ../ext/mbedtls/library/pkcs11.c
    ../ext/mbedtls/library/pkcs12.c
    ../ext/mbedtls/library/pkcs5.c
    ../ext/mbedtls/library/pkparse.c
    ../ext/mbedtls/library/pkwrite.c
    ../ext/mbedtls/library/platform.c
    ../ext/mbedtls/library/platform_util.c
    ../ext/mbedtls/library/poly1305.c
    ../ext/mbedtls/library/ripemd160.c
    ../ext/mbedtls/library/rsa.c
    ../ext/mbedtls/library/rsa_internal.c
    ../ext/mbedtls/library/sha1.c
    ../ext/mbedtls/library/sha256.c
    ../ext/mbedtls/library/sha512.c
    ../ext/mbedtls/library/ssl_cache.c
    ../ext/mbedtls/library/ssl_ciphersuites.c
    ../ext/mbedtls/library/ssl_cli.c
    ../ext/mbedtls/library/ssl_cookie.c
    ../ext/mbedtls/library/ssl_srv.c
    ../ext/mbedtls/library/ssl_ticket.c
    ../ext/mbedtls/library/ssl_tls.c
    ../ext/mbedtls/library/threading.c
    ../ext/mbedtls/library/timing.c
    ../ext/mbedtls/library/version.c
    ../ext/mbedtls/library/version_features.c
    ../ext/mbedtls/library/x509.c
    ../ext/mbedtls/library/x509_create.c
    ../ext/mbedtls/library/x509_crl.c
    ../ext/mbedtls/library/x509_crt.c
    ../ext/mbedtls/library/x509_csr.c
    ../ext/mbedtls/library/x509write_crt.c
    ../ext/mbedtls/library/x509write_csr.c
    ../ext/mbedtls/library/xtea.c
    )

FILE(
    GLOB
    SE_SOURCES

    ../sss/ex/src/ex_sss_boot.c
    ../sss/ex/src/ex_sss_boot_connectstring.c
    ../sss/ex/src/ex_sss_se05x.c
    ../sss/ex/src/ex_sss_se05x_auth.c
    ../sss/src/*.c

    ../sss/src/se05x/fsl_sss_se05x_apis.c
    ../sss/src/se05x/fsl_sss_se05x_mw.c
    ../sss/src/se05x/fsl_sss_se05x_policy.c

    ../hostlib/hostLib/libCommon/infra/*.c

    ../hostlib/hostLib/libCommon/smCom/smCom.c
    ../hostlib/hostLib/platform/rsp/se05x_reset.c
    ../hostlib/hostLib/platform/generic/sm_timer.c

    ../hostlib/hostLib/se05x/src/se05x_ECC_curves.c
    ../hostlib/hostLib/se05x/src/se05x_mw.c
    ../hostlib/hostLib/se05x/src/se05x_tlv.c
    ../hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c

    # T1oI2C files
    ../hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
    ../hostlib/hostLib/libCommon/smCom/T1oI2C/*.c
    ../hostlib/hostLib/platform/linux/i2c_a7.c

    ##### Mbedtls Host crypto support
    ../sss/src/mbedtls/fsl_sss_mbedtls_apis.c
    ../sss/src/keystore/keystore_pc.c
    ../sss/src/keystore/keystore_cmn.c

    ##### Authenticated session to se05x
    #../sss/ex/src/ex_sss_scp03_auth.c
    #../sss/src/se05x/fsl_sss_se05x_eckey.c
    #../sss/src/se05x/fsl_sss_se05x_scp03.c
    #../hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c

    ../hostlib/hostLib/mbedtls/src/ecdh_alt.c
    ../hostlib/hostLib/mbedtls/src/rsa_alt.c
    ../sss/plugin/mbedtls/ecdh_alt_ax.c
    ../sss/plugin/mbedtls/sss_mbedtls.c
    ../sss/plugin/mbedtls/sss_mbedtls_rsa.c

    ../sss/plugin/mbedtls/port/ksdk/ecp_curves_alt.c
    ../sss/plugin/mbedtls/port/ksdk/ecp_alt.c
)

add_executable(${PROJECT_NAME} ../sss/ex/mbedtls/ex_sss_ssl2.c ${MBEDTLS_SOURCES} ${SE_SOURCES})

FILE(
    GLOB
    INC_DIR
    ../../simw-top
    ../sss/inc
    ../sss/port/default
    ../sss/ex/src
    ../sss/ex/inc
    ../hostlib/hostLib/inc
    ../hostlib/hostLib/libCommon/infra
    ../hostlib/hostLib/libCommon/smCom
    ../hostlib/hostLib/libCommon/smCom/T1oI2C
    ../hostlib/hostLib/se05x_03_xx_xx
    ../hostlib/hostLib/platform/inc
    ../hostlib/hostLib/libCommon/smCom
    ../sss/plugin/mbedtls
    ../ext/mbedtls/include
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ${INC_DIR}
    )


TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PUBLIC
    MBEDTLS_CONFIG_FILE=\"sss_mbedtls_x86_config.h\"
)

ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DSMCOM_T1oI2C)
ADD_DEFINITIONS(-DT1oI2C)
ADD_DEFINITIONS(-DT1oI2C_UM11225)



#########################################################################################


project (ssl2_server)

add_executable( ${PROJECT_NAME}
    ../ext/mbedtls/programs/ssl/ssl_server2.c
    ../ext/mbedtls/programs/ssl/query_config.c
    ${SE_SOURCES}
    ${MBEDTLS_SOURCES}
    )

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ${INC_DIR}
    )

TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PUBLIC
    MBEDTLS_CONFIG_FILE=\"sss_mbedtls_x86_config.h\"
)
