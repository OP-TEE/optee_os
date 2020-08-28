/*
* Copyright 2019 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

/** @file
 *
 * @addtogroup param_check
 *
 * @{
 *
 * nxEnsure.h:  Helper parameter assertion check macros.
 *
 * Pre Condition: The source file must have included nxLog
 *                header file.
 *
 * Project:  SecureIoTMW
 *
 *
 */

#ifndef HOSTLIB_HOSTLIB_INC_NXENSURE_H_
#define HOSTLIB_HOSTLIB_INC_NXENSURE_H_

/* *****************************************************************************************************************
 *   Includes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */

/** Build time over-ride if we want to enable/disable Warning Prints
 *
 * During debug builds, it makes sense to print them,
 * During retail builds, such loggings would be of any use and remove and reduce code size.
 *
 */
#ifndef NX_ENSURE_DO_LOG_MESSAGE
#define NX_ENSURE_DO_LOG_MESSAGE 1
#endif /* NX_ENSURE_DO_LOG_MESSAGE */

/**
 * @brief Waring print of the parameter ``strCONDITION``
 *
 * @warning NX_ENSURE_MESSAGE is an internal message/API to this file.
 *          Do not use directly.
 *
 */
#if NX_ENSURE_DO_LOG_MESSAGE
#   define NX_ENSURE_MESSAGE(strCONDITION)   \
        LOG_W("nxEnsure:'" strCONDITION "' failed. At Line:%d Function:%s", __LINE__, __FUNCTION__)
#else /* NX_ENSURE_DO_LOG_MESSAGE */
#   define NX_ENSURE_MESSAGE(strCONDITION)  /* No Message */
#endif /* NX_ENSURE_DO_LOG_MESSAGE */

/**
 * @brief Waring print of the parameter ``strCONDITION``
 *
 * @warning NX_ENSURE_MESSAGE is an internal message/API to this file.
 *          Do not use directly.
 *
 */
#if NX_ENSURE_DO_LOG_MESSAGE
#   define NX_ENSURE_MESSAGE(strCONDITION)   \
        LOG_W("nxEnsure:'" strCONDITION "' failed. At Line:%d Function:%s", __LINE__, __FUNCTION__)
#else /* NX_ENSURE_DO_LOG_MESSAGE */
#   define NX_ENSURE_MESSAGE(strCONDITION)  /* No Message */
#endif /* NX_ENSURE_DO_LOG_MESSAGE */

/** If condition fails, goto :cleanup label
 *
 * @code{.c}
 *
 *  {
 *      ...
 *
 *      status = Operation1();
 *      ENSURE_OR_GO_CLEANUP(0 == status);
 *
 *      status = Operation2();
 *      ENSURE_OR_GO_CLEANUP(0 == status);
 *
 *      ...
 *
 *  cleanup:
 *      return status;
 *  }
 *
 * @endcode
 *
 */
#define ENSURE_OR_GO_CLEANUP(CONDITION) \
    if (!(CONDITION)) { \
        NX_ENSURE_MESSAGE(#CONDITION); \
        goto cleanup; \
    }

/** If condition fails, goto :exit label
 *
 * @code{.c}
 *
 *  {
 *      ...
 *
 *      status = Operation1();
 *      ENSURE_OR_GO_EXIT(0 == status);
 *
 *      status = Operation2();
 *      ENSURE_OR_GO_EXIT(0 == status);
 *
 *      ...
 *
 *  exit:
 *      return status;
 *  }
 *
 * @endcode
 *
 */
#define ENSURE_OR_GO_EXIT(CONDITION) \
    if (!(CONDITION)) { \
        NX_ENSURE_MESSAGE(#CONDITION); \
        goto exit; \
    }

/** If condition fails, break.
 *
 * Sample Usage:
 *
 * @code{.c}
 *
 * int SomeAPI()
 * {
 *     ...
 *
 *     do {
 *         status = Operation1();
 *         ENSURE_OR_BREAK(0 == status);
 *
 *         status = Operation2();
 *         ENSURE_OR_BREAK(0 == status);
 *
 *         ...
 *
 *     } while(0);
 *
 *     return status;
 * }
 *
 * @endcode
 *
 */
#define ENSURE_OR_BREAK(CONDITION) \
    if (!(CONDITION)) { \
        NX_ENSURE_MESSAGE(#CONDITION); \
        break; \
    }

/** If condition fails, return
 *
 *
 * @code{.c}
 *
 *  void SomeAPI()
 *  {
 *      ...
 *
 *      status = Operation1();
 *      ENSURE_OR_RETURN(0 == status);
 *
 *      status = Operation2();
 *      ENSURE_OR_RETURN(0 == status);
 *
 *      ...
 *
 *      return;
 *  }
 *
 * @endcode
 *
 * @warning This macro introduces system of mutliple
 *          returns from a function which is not
 *          easy to debug/trace through and hence
 *          not recommended.
 *
 */
#define ENSURE_OR_RETURN(CONDITION) \
    if (!(CONDITION)) { \
        NX_ENSURE_MESSAGE(#CONDITION); \
        return; \
    }

/** If condition fails, return
 *
 *
 * @code{.c}
 *
 *  int SomeAPI()
 *  {
 *      ...
 *
 *      status = Operation1();
 *      ENSURE_OR_RETURN_ON_ERROR(0 == status, ERR_FAIL);
 *
 *      status = Operation2();
 *      ENSURE_OR_RETURN_ON_ERROR(0 == status, ERR_NOT_ENOUGH_SPACE);
 *
 *      ...
 *
 *      return 0;
 *  }
 *
 * @endcode
 *
 * @warning This macro introduces system of mutliple
 *          returns from a function which is not
 *          easy to debug/trace through and hence
 *          not recommended.
 *
 */
#define ENSURE_OR_RETURN_ON_ERROR(CONDITION, RETURN_VALUE) \
    if (!(CONDITION)) { \
        NX_ENSURE_MESSAGE(#CONDITION); \
        return RETURN_VALUE; \
    }

/** If condition fails, goto quit with return value status updated.
 *
 *
 * @code{.c}
 *
 *  int SomeAPI()
 *  {
        int status = 0;
 *      ...
 *
 *      value = Operation1();
 *      ENSURE_OR_QUIT_WITH_STATUS_ON_ERROR(0 == value, status, ERR_FAIL);
 *
 *      value = Operation2();
 *      ENSURE_OR_QUIT_WITH_STATUS_ON_ERROR(0 == value, status, ERR_NOT_ENOUGH_SPACE);
 *
 *      ...
 *  quit:
 *      return status;
 *  }
 *
 * @endcode
 *
 * @warning This macro introduces system of mutliple
 *          returns from a function which is not
 *          easy to debug/trace through and hence
 *          not recommended.
 *
 */
#define ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(CONDITION, STATUS, RETURN_VALUE) \
    if (!(CONDITION)) { \
        NX_ENSURE_MESSAGE(#CONDITION); \
        STATUS = RETURN_VALUE; \
        goto exit; \
    }

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 *   Extern Variables
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 *   Function Prototypes
 * ***************************************************************************************************************** */

/** @} */

#endif /* HOSTLIB_HOSTLIB_INC_NXENSURE_H_ */
