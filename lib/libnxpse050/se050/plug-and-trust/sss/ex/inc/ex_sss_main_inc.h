/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Common, Re-Usable main implementation */
/* Include this header file only once in the application */

/*
 *  Applications control the boot flow by defining these macros.
 *
 *
 *  - EX_SSS_BOOT_PCONTEXT : Pointer to ex_sss_boot_ctx_t
 *      This allows that boot framework do not blindly rely on
 *      global variables.
 *
 *  - EX_SSS_BOOT_DO_ERASE : Delete all objects on boot up if 1
 *      Few examples expect the IC is *empty*, and few examples
 *      expect to work with previously provisioned/persisted data.
 *      This variable allows to over-ride that behaviour.
 *
 *  - EX_SSS_BOOT_EXPOSE_ARGC_ARGV : Expose ARGC & ARGV from Command
 *      line to Application.
 *      When running from PC/Linux/OSX, command line arguments allow
 *      to choose extra command line parameters, e.g. Input/Output
 *      certificate or signing/verifying data.
 *      But on embedded platforms, such feature is not possible to
 *      achieve.
 *
 *  Optional variables:
 *
 *  - EX_SSS_BOOT_RTOS_STACK_SIZE : For RTOS based system,
 *      this is over-ridden and passed to RTOS based example
 *      boot up.  It sets value needed for new task.
 *      Please note, FREE RTOS will reserve
 *      EX_SSS_BOOT_RTOS_STACK_SIZE * sizeof(UBaseType_t)
 *      bytes.
 *
 *  - EX_SSS_BOOT_OPEN_HOST_SESSION : For examples that do not
 *      need host side implementation, his allows to skip opening
 *      the host session. (Host session is needed to either re-verify
 *      test data at host, or for SCP03).
 *      By default this is enabled.
 *
 *
 */

#if defined(FRDM_KW41Z) || defined(FRDM_K64F) || defined(IMX_RT) || defined(LPC_55x)
#define HAVE_KSDK
#endif

#ifdef HAVE_KSDK
#include "ex_sss_main_inc_ksdk.h"
#endif

#if defined(__linux__) && defined(T1oI2C)
#if SSS_HAVE_APPLET_SE05X_IOT
#include "ex_sss_main_inc_linux.h"
#endif
#endif
#include <string.h> /* memset */

#include "PlugAndTrust_Pkg_Ver.h"
#include "string.h" /* memset */

#if AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1
#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#include "task.h"
#endif

#if SSS_HAVE_A71CH
#include "ex_a71ch_scp03.h"
#endif

#ifdef EX_SSS_BOOT_PCONTEXT
#define PCONTEXT EX_SSS_BOOT_PCONTEXT
#else
#define PCONTEXT (NULL)
#endif

#if !defined(EX_SSS_BOOT_DO_ERASE)
#error EX_SSS_BOOT_DO_ERASE must be set to 0 or 1
#endif

#if !defined(EX_SSS_BOOT_EXPOSE_ARGC_ARGV)
#error EX_SSS_BOOT_EXPOSE_ARGC_ARGV must be set to 0 or 1
#endif

#if EX_SSS_BOOT_EXPOSE_ARGC_ARGV
static int gex_sss_argc;
static const char **gex_sss_argv;
#endif

#if !defined(EX_SSS_BOOT_OPEN_HOST_SESSION)
#define EX_SSS_BOOT_OPEN_HOST_SESSION 1
#endif

#if !defined(EX_SSS_BOOT_RTOS_STACK_SIZE)
#define EX_SSS_BOOT_RTOS_STACK_SIZE 8500
#endif

#if AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1
static TaskHandle_t gSSSExRtosTaskHandle = NULL;
static void sss_ex_rtos_task(void *ctx);
#if INCLUDE_uxTaskGetStackHighWaterMark
void sss_ex_rtos_stack_size(const char *when);
#endif // INCLUDE_uxTaskGetStackHighWaterMark
#endif /* No RTOS, No Embedded */

int main(int argc, const char *argv[])
{
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    const char *portName;

#if EX_SSS_BOOT_EXPOSE_ARGC_ARGV
    gex_sss_argc = argc;
    gex_sss_argv = argv;
#endif // EX_SSS_BOOT_EXPOSE_ARGC_ARGV

#ifdef HAVE_KSDK
    ex_sss_main_ksdk_bm();
#endif // HAVE_KSDK

#if defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT
    ex_sss_main_linux_conf();
#endif // defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT

    LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);

#ifdef EX_SSS_BOOT_PCONTEXT
    memset((EX_SSS_BOOT_PCONTEXT), 0, sizeof(*(EX_SSS_BOOT_PCONTEXT)));
#endif // EX_SSS_BOOT_PCONTEXT

#if AX_EMBEDDED
    portName = NULL;
#else
    status = ex_sss_boot_connectstring(argc, argv, &portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_boot_connectstring Failed");
        goto cleanup;
    }
#endif // AX_EMBEDDED

#if defined(EX_SSS_BOOT_SKIP_SELECT_APPLET) && (EX_SSS_BOOT_SKIP_SELECT_APPLET == 1)
    (PCONTEXT)->se05x_open_ctx.skip_select_applet = 1;
#endif

#if AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1
    if (xTaskCreate(&sss_ex_rtos_task,
            "sss_ex_rtos_task",
            EX_SSS_BOOT_RTOS_STACK_SIZE,
            (void *)portName,
            (tskIDLE_PRIORITY),
            &gSSSExRtosTaskHandle) != pdPASS) {
        LOG_E("Task creation failed!.\r\n");
        while (1)
            ;
    }

    /* Run RTOS */
    vTaskStartScheduler();

#else /* No RTOS, No Embedded */

#if !AX_EMBEDDED
    if (ex_sss_boot_isHelp(portName)) {
        memset(PCONTEXT, 0, sizeof(*PCONTEXT));
#if EX_SSS_BOOT_EXPOSE_ARGC_ARGV
        /* so that tool can fetchup last value */
        gex_sss_argc++;
#endif // EX_SSS_BOOT_EXPOSE_ARGC_ARGV
        goto before_ex_sss_entry;
    }
#endif

    status = ex_sss_boot_open(PCONTEXT, portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed");
        goto cleanup;
    }

#if EX_SSS_BOOT_DO_ERASE
    status = ex_sss_boot_factory_reset((PCONTEXT));
#endif

    if (kType_SSS_SubSystem_NONE == ((PCONTEXT)->session.subsystem)) {
        /* Nothing to do. Device is not opened
         * This is needed for the case when we open a generic communication
         * channel, without being specific to SE05X
         */
    }
    else {
        status = ex_sss_kestore_and_object_init((PCONTEXT));
        if (kStatus_SSS_Success != status) {
            LOG_E("ex_sss_kestore_and_object_init Failed");
            goto cleanup;
        }
    }

#if EX_SSS_BOOT_OPEN_HOST_SESSION && SSS_HAVE_HOSTCRYPTO_ANY
    ex_sss_boot_open_host_session((PCONTEXT));
#endif

#if SSS_HAVE_A71CH && SSS_HAVE_A71CH_AUTH_SCP03
    LOG_I("A71CH SCP03 add-on");
    {
        // Variables used by calls to legacy API
        U8 sCounter[3];
        U16 sCounterLen = sizeof(sCounter);
        U16 sw          = 0;
        U8 scpKeyEncBase[SCP_KEY_SIZE];
        U8 scpKeyMacBase[SCP_KEY_SIZE];
        U8 scpKeyDekBase[SCP_KEY_SIZE];

        LOG_I("** Establish SCP03 session: Start **");
        status = ex_a71ch_FetchRandomScp03Keys(scpKeyEncBase, scpKeyMacBase, scpKeyDekBase);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = ex_a71ch_SetSeScp03Keys(scpKeyEncBase, scpKeyMacBase, scpKeyDekBase);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Clear host-side SCP03 channel state");
        DEV_ClearChannelState();

        LOG_I("SCP_Authenticate()");
        sw     = SCP_Authenticate(scpKeyEncBase, scpKeyMacBase, scpKeyDekBase, SCP_KEY_SIZE, sCounter, &sCounterLen);
        status = (sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail;
        ENSURE_OR_GO_CLEANUP(sw == SW_OK);
        LOG_I("** Establish SCP03 session: End **");
    }
#endif // SSS_HAVE_A71CH && SSS_HAVE_A71CH_AUTH_SCP03

#if !AX_EMBEDDED
before_ex_sss_entry:
#endif

    status = ex_sss_entry((PCONTEXT));
    LOG_I("ex_sss Finished");
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
        goto cleanup;
    }
#endif /* No RTOS, No Embedded */

    goto cleanup;

cleanup:
#ifdef EX_SSS_BOOT_PCONTEXT
    ex_sss_session_close((EX_SSS_BOOT_PCONTEXT));
#endif
    if (kStatus_SSS_Success == status) {
        ret = 0;
#if defined(HAVE_KSDK) && HAVE_KSDK_LED_APIS == 1
        ex_sss_main_ksdk_success();
#endif
#if defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT
        ex_sss_main_linux_unconf();
#endif // defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT
    }
    else {
        LOG_E("!ERROR! ret != 0.");
        ret = 1;
#if defined(HAVE_KSDK) && HAVE_KSDK_LED_APIS == 1
        ex_sss_main_ksdk_failure();
#endif
    }
    return ret;
}

#if AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1
static void sss_ex_rtos_task(void *ctx)
{
    sss_status_t status;

#if INCLUDE_uxTaskGetStackHighWaterMark
    sss_ex_rtos_stack_size("Boot");
#endif // INCLUDE_uxTaskGetStackHighWaterMark

    ex_sss_main_ksdk_boot_rtos_task();

    status = ex_sss_boot_open(PCONTEXT, (const char *)ctx);

    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed.");
        goto exit;
    }

    status = ex_sss_kestore_and_object_init((PCONTEXT));

    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_kestore_and_object_init Failed");
        goto exit;
    }

#if INCLUDE_uxTaskGetStackHighWaterMark
    sss_ex_rtos_stack_size("Before:ex_sss_entry");
#endif // INCLUDE_uxTaskGetStackHighWaterMark

#if EX_SSS_BOOT_DO_ERASE
    status = ex_sss_boot_factory_reset((PCONTEXT));
    if (kStatus_SSS_Success != status) {
        LOG_W("ex_sss_boot_factory_reset Failed");
    }
#if INCLUDE_uxTaskGetStackHighWaterMark
    sss_ex_rtos_stack_size("after:erase");
#endif // INCLUDE_uxTaskGetStackHighWaterMark
#endif

#if SSS_HAVE_A71CH
#if EX_SSS_BOOT_OPEN_HOST_SESSION
    ex_sss_boot_open_host_session((PCONTEXT));
#endif
#endif

    status = ex_sss_entry((PCONTEXT));

    LOG_I("ex_sss Finished");
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
    }

#if INCLUDE_uxTaskGetStackHighWaterMark
    sss_ex_rtos_stack_size("After:ex_sss_entry");
#endif // INCLUDE_uxTaskGetStackHighWaterMark

exit:
    vTaskDelete(NULL);
}

#if INCLUDE_uxTaskGetStackHighWaterMark
void sss_ex_rtos_stack_size(const char *when)
{
#if LOG_INFO_ENABLED
    UBaseType_t stackused;
    stackused = EX_SSS_BOOT_RTOS_STACK_SIZE - uxTaskGetStackHighWaterMark(gSSSExRtosTaskHandle);
    LOG_I("STACK USED [%s] %d", when, sizeof(UBaseType_t) * stackused);
#endif
}
#endif /* INCLUDE_uxTaskGetStackHighWaterMark */

#endif /* No RTOS, No Embedded */
