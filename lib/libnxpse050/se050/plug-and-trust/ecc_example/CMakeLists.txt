CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

project (ex_ecc)

FILE(
    GLOB
    SOURCES
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

    ##### Openssl Host crypto support
    #../sss/src/openssl/fsl_sss_openssl_apis.c
    #../sss/src/keystore/keystore_cmn.c
    #../sss/src/keystore/keystore_openssl.c
    #../sss/src/keystore/keystore_pc.c

    ##### Mbedtls Host crypto support
    #../sss/src/mbedtls/fsl_sss_mbedtls_apis.c
    #../sss/src/keystore/keystore_cmn.c
    #../sss/src/keystore/keystore_pc.c

    ##### Authenticated session to se05x
    #../sss/ex/src/ex_sss_scp03_auth.c
    #../sss/src/se05x/fsl_sss_se05x_eckey.c
    #../sss/src/se05x/fsl_sss_se05x_scp03.c
    #../hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c
)

add_executable(${PROJECT_NAME} ../sss/ex/ecc/ex_sss_ecc.c ${SOURCES})

#TARGET_LINK_LIBRARIES(${PROJECT_NAME} ssl crypto)


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
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ${INC_DIR}
    )


ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DSMCOM_T1oI2C)
ADD_DEFINITIONS(-DT1oI2C)
ADD_DEFINITIONS(-DT1oI2C_UM11225)
