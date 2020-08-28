Introduction on Plug & Trust Middleware Mini Package
====================================================================

Plug and Trust middleware mini package contains the minimum files required to
connect to se05x using t1oi2c protocol. The package is tested on
*Raspberry-Pi* with ``T=1 overI2C``.

The complete Plug and Trust middleware package can be downloaded from
https://www.nxp.com/products/:SE050. The package has support for other
platforms.

- iMX6UL, iMX8MQ - Linux
- Freedom K64F, i.MX RT 1060, LPC55S - FreeRTOS/Without RTOS
- Hikey 960 - Android
- Windows PC(Visual Studio)

It also includes other api usage examples, ssscli (command line tool to use
se050), cloud connectivity examples, openssl engine, pkcs11 interface, AWS
Greengrass, OPCUA and more. More details regarding SE050 and other detailed
application notes can be found at https://www.nxp.com/products/:SE050.


Folder structure of the Mini Pacakge
-------------------------------------------------------------

The folder structure of mini package is as under::

    ├───ecc_example
    ├───hostlib
    │   └───hostLib
    │       ├───inc
    │       ├───libCommon
    │       │   ├───infra
    │       │   ├───nxScp
    │       │   └───smCom
    │       │       └───T1oI2C
    │       ├───mbedtls
    │       │   └───src
    │       ├───platform
    │       │   ├───generic
    │       │   ├───inc
    │       │   ├───linux
    │       │   └───rsp
    │       ├───se05x
    │       │   └───src
    │       └───se05x_03_xx_xx
    └───sss
        ├───ex
        │   ├───ecc
        │   ├───inc
        │   └───src
        ├───inc
        ├───plugin
        │   └───mbedtls
        ├───port
        │   └───default
        └───src
            ├───keystore
            ├───mbedtls
            ├───openssl
            └───se05x

Important folders are as under:

:ecc_example:  ecc sign and verify example. (Tested on Raspberry Pi with openssl 1.1.1)

:hostlib:  This folder contains the common part of host library e.g. ``T=1oI2C`` communication
           protocol stack, SE050 APIs, etc.

:sss:  This folder contains the **SSS APIs** interface to the Application Layer.


Prerequisite
-------------------------------------------------------------
- Linux should be running on the Raspberry Pi development board,
  the release was tested with Raspbian Buster (``4.19.75-v7l+``)
- SE050 connected to i2c-1 port of Raspberry Pi.


ECC example
-------------------------------------------------------------

This example demonstrates Elliptic Curve Cryptography sign and verify
operation using SSS APIs. (``/sss/ex/ecc/ex_sss_ecc.c``) Execute the command
below to test the ecc example::

    cd ecc_example
    mkdir build
    cd build
    cmake ..
    cmake --build .
    ./ex_ecc


Build Applications using Mini Package
-------------------------------------------------------------

Use the source file in `sss/ex` folder to open the session to se05x.
Applications code should start with function `ex_sss_entry`::

    sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)

Refer the example `ecc_example`.
Example File - `/sss/ex/ecc/ex_sss_ecc.c`


To enable authenticated session to se050, make the following changes,

1. Enable any host crypto (Mbedtls or openssl or User crypto) in
   ``fsl_sss_ftr.h`` file. Refer,

- For Openssl:     Refer section - *Openssl host crypto in mini package*
- For Mbedtls:     Refer section - *Mbedtls host crypto in mini package*
- For User Crypto: Refer section - *User host crypto in mini package*


2. Enable the below macros in ``fsl_sss_ftr.h`` file:

- ``#define SSS_HAVE_SCP_SCP03_SSS 1``
- ``#define SSSFTR_SE05X_AuthSession 1``

3. Below settings can be used to authenticate with SE (Refer SE050 - User
   Guidelines in https://www.nxp.com/products/:SE050 for more details on session
   authentication)

- ``SSS_HAVE_SE05X_AUTH_USERID``
- ``SSS_HAVE_SE05X_AUTH_AESKEY``
- ``SSS_HAVE_SE05X_AUTH_ECKEY``
- ``SSS_HAVE_SE05X_AUTH_PLATFSCP03``
- ``SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03``
- ``SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03``
- ``SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03``


4. Include the below source files for autheticated session open,

- ``sss/ex/src/ex_sss_scp03_auth.c``
- ``sss/src/se05x/fsl_sss_se05x_eckey.c``
- ``sss/src/se05x/fsl_sss_se05x_scp03.c``
- ``hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c``


Openssl host crypto in mini package
-------------------------------------------------------------

Enable/disable the openssl host crypto by changing the below definition in
``fsl_sss_ftr.h`` file::

    /** Use OpenSSL as host crypto */
    #define SSS_HAVE_HOSTCRYPTO_OPENSSL 1

Include the below files for openssl host crypto support
- ``sss/src/openssl/fsl_sss_openssl_apis.c``
- ``sss/src/keystore/keystore_cmn.c``
- ``sss/src/keystore/keystore_openssl.c``
- ``sss/src/keystore/keystore_pc.c``

Link the openssl library (version 1.1) as,
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ssl crypto)


Mbedtls host crypto in mini package
-------------------------------------------------------------

Enable/disable the mbedtls host crypto by changing the below definition in
``fsl_sss_ftr.h`` file::

    /** Use mbedTLS as host crypto */
    #define SSS_HAVE_HOSTCRYPTO_MBEDTLS 1

Include the below file for mbedtls host crypto support,

- ``sss/src/mbedtls/fsl_sss_mbedtls_apis.c``
- ``sss/src/keystore/keystore_pc.c``
- ``sss/src/keystore/keystore_cmn.c``

Mbedtls applications depend on the following files to use se05x for crypto
operations. Include the following files for compilation along with the mbedtls
stack. (Tested with mbedtls-2.16.2). Mbedtls client server example using the
below files is expalined in the next section,

- ``/hostlib/hostLib/mbedtls/src/ecdh_alt.c``
- ``/hostlib/hostLib/mbedtls/src/rsa_alt.c``
- ``/sss/plugin/mbedtls/ecdh_alt_ax.c``
- ``/sss/plugin/mbedtls/sss_mbedtls.c``
- ``/sss/plugin/mbedtls/sss_mbedtls_rsa.c``
- ``/sss/plugin/mbedtls/port/ksdk/ecp_curves_alt.c``
- ``/sss/plugin/mbedtls/port/ksdk/ecp_alt.c``

Note: Exclude the file ``mbedtls/library/ecdh.c`` from mbedtls stack for compilation.

Also add compile defination ``MBEDTLS_CONFIG_FILE`` to use the correct mbedtls config file::

    TARGET_COMPILE_DEFINITIONS(
        ${PROJECT_NAME}
        PUBLIC
        MBEDTLS_CONFIG_FILE=\"sss_mbedtls_x86_config.h\"
    )

.. note::

    Remove linking the openssl library in ``ecc_example/CMakeLists.txt``, if
    the example is built for mbedtls, ``TARGET_LINK_LIBRARIES(${PROJECT_NAME}
    ssl crypto)``



TLS Client Server Example using MbedTLS stack
-------------------------------------------------------------

This example demonstrates TLS client server connection using mbedtls stack.
(``mbedtls_cli_srv``). Mbedtls client example is modified to use the
client key and certificates from secure element. Modified mbedtls client
example - ``sss/ex/mbedtls/ex_sss_ssl2.c``

Prerequisite for the demo:

- Copy mbedtls (``mbedtls-2.16.2``) stack to ``ext/`` location,
- client key provisoned inside SE050 with key id ``0x20181001``,
- client certificate provisoned inside SE050 with key id ``0x20181002``,
- Root CA public key provisoned inside SE050 with key id ``0x7DCCBB22``,

Enable mbedtls host crypto in ``fsl_sss_ftr.h`` file.  Execute the command
below to build mbedtls client and server examples::

    cd mbedtls_cli_srv
    mkdir build
    cd build
    cmake ..
    cmake --build .


Run mbedtls server as::

    ./ssl2_server exchanges=1 \
        force_version=tls1_2 \
        debug_level=1 \
        ca_file=<ROOT_CA_CERT> \
        auth_mode=required \
        key_file=<SERVER_KEY> \
        crt_file=<SERVER_CERT>

Run mbedtls client as::

    ./ssl2_client server_name=localhost \
        exchanges=1 \
        force_version=tls1_2 \
        debug_level=1 \
        ca_file=<ROOT_CA_CERT> \
        auth_mode=required \
        key_file=none \
        crt_file=none \
        force_ciphersuite=TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA \
        curves=secp256r1 none



User host crypto in mini package
-------------------------------------------------------------

Enable/disable the user host crypto by changing the below definition in ``fsl_sss_ftr.h`` file::

    #define SSS_HAVE_HOSTCRYPTO_USER 1

On enabling HOSTCRYPTO_USER, the user has to implement the required cryptographic function.
Implement the functions declared in file ``sss/inc/fsl_sss_user_apis.h``.

Refer Openssl host crypto implementation in - ``sss/src/mbedtls/fsl_sss_openssl_apis.c``.
Refer Mbedtls host crypto implementation in - ``sss/src/mbedtls/fsl_sss_mbedtls_apis.c``.



Port Mini package to different platform
-------------------------------------------------------------

To port the mini package to different platform, the i2c interface needs to be
ported. Exsisting implementation for i2c read/write on Raspberry Pi is in -
``hostlib/hostLib/platform/linux/i2c_a7.c``.

Other file that may require porting is -
``hostlib/hostLib/platform/generic/sm_timer.c``



Memory Details
-------------------------------------------------------------

Memory details of ex_ecc example on Raspberry Pi built with,

- No hostcrypto
- Plain session

::

    Text segment -- 182817 Bytes
    Data segment -- 416 Bytes
    Bss segment --- 2808 Bytes
    Total  -------- 186041 Bytes


Memory details of ex_ecc example on Raspberry Pi built with

- Openssl hostcrypto
- PlatformSCP + ECKey (EXFL_SE050_AUTH_ECKey_PlatfSCP03 ) session

::

    Text segment -- 290184 Bytes
    Data segment -- 1116 Bytes
    Bss segment --- 3692 Bytes
    Total  -------- 294992 Bytes

