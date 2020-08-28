/*
 * Copyright 2010-2014,2018-2019 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ESE Status Values - Function Return Codes
 */

#ifndef PHESESTATUS_H
#define PHESESTATUS_H

#include "phEseTypes.h"

/* Internally required by PHESESTVAL. */
#define PHESESTSHL8                          (8U)
/* Required by PHESESTVAL. */
#define PHESESTBLOWER                        ((ESESTATUS)(0x00FFU))

/*
 *  ESE Status Composition Macro
 *
 *  This is the macro which must be used to compose status values.
 *
 *  phEseCompID Component ID, as defined in phEseCompId.h .
 *  phEseStatus Status values, as defined in phEseStatus.h .
 *
 *  The macro is not required for the ESESTATUS_SUCCESS value.
 *  This is the only return value to be used directly.
 *  For all other values it shall be used in assignment and conditional statements, e.g.:
 *     ESESTATUS status = PHESESTVAL(phEseCompID, phEseStatus); ...
 *     if (status == PHESESTVAL(phEseCompID, phEseStatus)) ...
 */
#define PHESESTVAL(phEseCompID, phEseStatus)                                  \
            ( ((phEseStatus) == (ESESTATUS_SUCCESS)) ? (ESESTATUS_SUCCESS) :  \
                ( (((ESESTATUS)(phEseStatus)) & (PHESESTBLOWER)) |            \
                    (((uint16_t)(phEseCompID)) << (PHESESTSHL8)) ) )

/*
 * PHESESTATUS
 * Get grp_retval from Status Code
 */
#define PHESESTATUS(phEseStatus)  ((phEseStatus) & 0x00FFU)
#define PHESECID(phEseStatus)  (((phEseStatus) & 0xFF00U)>>8)

/*
 *  Status Codes
 *
 *  Generic Status codes for the ESE components. Combined with the Component ID
 *  they build the value (status) returned by each function.
 *  Example:
 *      grp_comp_id "Component ID" -  e.g. 0x10, plus
 *      status code as listed in this file - e.g. 0x03
 *      result in a status value of 0x0003.
 */

/*
 * The function indicates successful completion
 */
#define ESESTATUS_SUCCESS                                     (0x0000)

/*
 *  The function indicates successful completion
 */
#define ESESTATUS_OK                                (ESESTATUS_SUCCESS)

/*
 * At least one parameter could not be properly interpreted
 */
#define ESESTATUS_INVALID_PARAMETER                           (0x0001)

/*
 * Invalid buffer provided by application
 *  */
#define ESESTATUS_INVALID_BUFFER                           (0x0002)

/*
 * The buffer provided by the caller is too small
 */
#define ESESTATUS_BUFFER_TOO_SMALL                            (0x0003)

/*
 * Invalid class byte provided by application
 *  */
#define ESESTATUS_INVALID_CLA                           (0x0004)

/*
 * Invalid command pdu type provided by application
 *  */
#define ESESTATUS_INVALID_CPDU_TYPE                           (0x0005)

/*
 * Invalid command LE type provided by application
 *  */
#define ESESTATUS_INVALID_LE_TYPE                           (0x0007)

/*
 * Device specifier/handle value is invalid for the operation
 */
#define ESESTATUS_INVALID_DEVICE                              (0x0006)

/*
 * The function executed successfully but could have returned
 * more information than space provided by the caller
 */
#define ESESTATUS_MORE_FRAME                            (0x0008)

/*
 * No response from the remote device received: Time-out
 */
#define ESESTATUS_LAST_FRAME                                  (0x0009)

/*
 * CRC Error during data transaction with the device
 */
#define ESESTATUS_CRC_ERROR                                    (0x000A)

/*
 * SOF Error during data transaction with the device
 */
#define ESESTATUS_SOF_ERROR                                    (0x000B)

/*
 * Not enough resources Memory, Timer etc(e.g. allocation failed.)
 */
#define ESESTATUS_INSUFFICIENT_RESOURCES                      (0x000C)

/*
 * A non-blocking function returns this immediately to indicate
 * that an internal operation is in progress
 */
#define ESESTATUS_PENDING                                     (0x000D)

/*
 * A board communication error occurred
 * (e.g. Configuration went wrong)
 */
#define ESESTATUS_BOARD_COMMUNICATION_ERROR                   (0x000F)

/*
 * Invalid State of the particular state machine
 */
#define ESESTATUS_INVALID_STATE                               (0x0011)


/*
 * This Layer is Not initialized, hence initialization required.
 */
#define ESESTATUS_NOT_INITIALISED                             (0x0031)


/*
 * The Layer is already initialized, hence initialization repeated.
 */
#define ESESTATUS_ALREADY_INITIALISED                         (0x0032)


/*
 * Feature not supported
 */
#define ESESTATUS_FEATURE_NOT_SUPPORTED                       (0x0033)

/*
 * Parity Error
 */
#define ESESTATUS_PARITY_ERROR                              (0x0034)


/* The Registration command has failed because the user wants to register on
 * an element for which he is already registered
 */
#define ESESTATUS_ALREADY_REGISTERED                          (0x0035)

/*  Chained frame is being sent */
#define ESESTATUS_CHAINED_FRAME                          (0x0036)

/*
 * Single frame is sent
 */
#define ESESTATUS_SINGLE_FRAME                               (0x0037)

/*
 * A DESELECT event has occurred
 */
#define ESESTATUS_DESELECTED                                  (0x0038)

/*
 * A RELEASE event has occurred
 */
#define ESESTATUS_RELEASED                                    (0x0039)

/*
 * The operation is currently not possible or not allowed
 */
#define ESESTATUS_NOT_ALLOWED                                 (0x003A)

/*
 *  Other indicaated error sent by JCOP.
 */
#define ESESTATUS_OTHER_ERROR                                 (0x003C)
/*
 *  The system is busy with the firmware download operation.
 */
#define ESESTATUS_DWNLD_BUSY                                  (0x006E)

/*
 *  The system is busy with the previous operation.
 */
#define ESESTATUS_BUSY                                        (0x006F)


/* NDEF Mapping error codes */

/* The remote device (type) is not valid for this request. */
#define ESESTATUS_INVALID_REMOTE_DEVICE                       (0x001D)

/* Read operation failed */
#define ESESTATUS_READ_FAILED                                 (0x0014)

/*
 * Write operation failed
 */
#define ESESTATUS_WRITE_FAILED                                (0x0015)


/* Non Ndef Compliant */
#define ESESTATUS_NO_NDEF_SUPPORT                             (0x0016)

/* resend the frame with seq_counter 0*/
#define ESESTATUS_RESET_SEQ_COUNTER_FRAME_RESEND                          (0x001A)

/* Incorrect number of bytes received from the card*/
#define ESESTATUS_INVALID_RECEIVE_LENGTH                      (0x001B)

/* The data format/composition is not understood/correct. */
#define ESESTATUS_INVALID_FORMAT                              (0x001C)


/* There is not sufficient storage available. */
#define ESESTATUS_INSUFFICIENT_STORAGE                        (0x001F)

/* The last command would be re-sent */
#define ESESTATUS_FRAME_RESEND                                (0x0023)

/* The write timeout error */
#define ESESTATUS_WRITE_TIMEOUT                              (0x0024)

/*
 * Response Time out for the control message(ESEC not responded)
 */
#define ESESTATUS_RESPONSE_TIMEOUT                            (0x0025)

/*
 * Resend the last R Frame
 */
#define ESESTATUS_FRAME_RESEND_R_FRAME                          (0x0026)

/*
 * Send next chained frame
 */
#define ESESTATUS_SEND_NEXT_FRAME                             (0x0027)

/*
 * Protocol revovery started
 */
#define ESESTATUS_REVOCERY_STARTED                        (0x0028)

/*
 * Single Target Detected
 */
#define ESESTATUS_SEND_R_FRAME                            (0x0029)

/*
 * Resend the  RNAK
 */

#define ESESTATUS_FRAME_RESEND_RNAK                          (0x0030)

/*
 * Resend the last R Frame
 */
#define ESESTATUS_FRAME_SEND_R_FRAME                          (0x003B)

/*
 * Unknown error Status Codes
 */
#define ESESTATUS_UNKNOWN_ERROR                               (0x00FE)

/*
 * Status code for failure
 */
#define ESESTATUS_FAILED                                      (0x00FF)

/*
 * The function/command has been aborted
 */
#define ESESTATUS_CMD_ABORTED                                 (0x0002)

/*
 * No target found after poll
 */
#define ESESTATUS_NO_TARGET_FOUND                             (0x000A)

/* Attempt to disconnect a not connected remote device. */
#define ESESTATUS_NO_DEVICE_CONNECTED                         (0x000B)


/* requesting a resynchronization */
#define ESESTATUS_RESYNCH_REQ                        (0x000E)

/*
 * acknowledging resynchronization
 */
#define ESESTATUS_RESYNCH_RES                      (0x0010)

/*
 * S-block offering a maximum size of the information field
 */
#define ESESTATUS_IFS_REQ                              (0x001E)

/* S-block offering a maximum size of the information field */
#define ESESTATUS_IFS_RES                              (0x0017)

/* S-block requesting a chain abortion */
#define ESESTATUS_ABORT_REQ                            (0x00F0)


/*S-block acknowledging the chain abortion*/
#define ESESTATUS_ABORT_RES                            (0x00F2)


/* S-block requesting a waiting time extension*/
#define ESESTATUS_WTX_REQ                              (0x00F5)

/* S-block acknowledging the waiting time extension */
#define ESESTATUS_WTX_RES                              (0x00F6)

/* S-block interface reset request */
#define ESESTATUS_RESET_REQ                            (0x00F7)

/* S-block interface reset response */
#define ESESTATUS_RESET_RES                            (0x00F8)

/* S-block requesting a end of apdu transfer*/
#define ESESTATUS_END_APDU_REQ                         (0x00F9)

/* S-block acknowledging end of apdu transfer*/
#define ESESTATUS_END_APDU_RES                         (0x00FA)

/*
 * Shutdown in progress, cannot handle the request at this time.
 */
#define ESESTATUS_SHUTDOWN                  (0x0091)

/*
 * Target is no more in RF field
 */
#define ESESTATUS_TARGET_LOST               (0x0092)

/*
 * Request is rejected
 */
#define ESESTATUS_REJECTED                  (0x0093)

/*
 * Target is not connected
 */
#define ESESTATUS_TARGET_NOT_CONNECTED      (0x0094)

/*
 * Invalid handle for the operation
 */
#define ESESTATUS_INVALID_HANDLE            (0x0095)

/*
 * Process aborted
 */
#define ESESTATUS_ABORTED                   (0x0096)

/*
 * Requested command is not supported
 */
#define ESESTATUS_COMMAND_NOT_SUPPORTED     (0x0097)

/*
 * Tag is not NDEF compilant
 */
#define ESESTATUS_NON_NDEF_COMPLIANT        (0x0098)

/*
 * Not enough memory available to complete the requested operation
 */
#define ESESTATUS_NOT_ENOUGH_MEMORY         (0x001F)

/*
 * Indicates incoming connection
 */
#define ESESTATUS_INCOMING_CONNECTION        (0x0045)

/*
 * Indicates Connection was successful
 */
#define ESESTATUS_CONNECTION_SUCCESS         (0x0046)

/*
 * Indicates Connection failed
 */
#define ESESTATUS_CONNECTION_FAILED          (0x0047)

#endif /* PHESESTATUS_H */
