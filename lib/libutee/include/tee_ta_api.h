/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

/* Based on GP TEE Internal API Specification Version 0.22 */
#ifndef TEE_TA_API_H
#define TEE_TA_API_H

#include <tee_api_defines.h>
#include <tee_api_types.h>

/* This is a null define in STE TEE environment */
#define TA_EXPORT

/*
 * TA Interface
 *
 * Each Trusted Application must provide the Implementation with a number
 * of functions, collectively called the “TA interface”. These functions
 * are the entry points called by the Trusted Core Framework to create the
 * instance, notify the instance that a new client is connecting, notify
 * the instance when the client invokes a command, etc.
 *
 * Trusted Application Entry Points:
 */

/*
 * The function TA_CreateEntryPoint is the Trusted Application's
 * constructor, which the Framework calls when it creates a new instance of
 * the Trusted Application. To register instance data, the implementation
 * of this constructor can use either global variables or the function
 * TEE_InstanceSetData.
 *
 * Return Value:
 * - TEE_SUCCESS: if the instance is successfully created, the function
 *   must return TEE_SUCCESS.
 * - Any other value: if any other code is returned the instance is not
 *   created, and no other entry points of this instance will be called.
 *   The Framework MUST reclaim all resources and dereference all objects
 *   related to the creation of the instance.
 *
 *   If this entry point was called as a result of a client opening a
 *   session, the error code is returned to the client and the session is
 *   not opened.
 */
TEE_Result TA_EXPORT TA_CreateEntryPoint(void);

/*
 * The function TA_DestroyEntryPoint is the Trusted Application‟s
 * destructor, which the Framework calls when the instance is being
 * destroyed.
 *
 * When the function TA_DestroyEntryPoint is called, the Framework
 * guarantees that no client session is currently open. Once the call to
 * TA_DestroyEntryPoint has been completed, no other entry point of this
 * instance will ever be called.
 *
 * Note that when this function is called, all resources opened by the
 * instance are still available. It is only after the function returns that
 * the Implementation MUST start automatically reclaiming resources left
 * opened.
 *
 * Return Value:
 * This function can return no success or error code. After this function
 * returns the Implementation MUST consider the instance destroyed and
 * reclaims all resources left open by the instance.
 */
void TA_EXPORT TA_DestroyEntryPoint(void);

/*
 * The Framework calls the function TA_OpenSessionEntryPoint when a client
 * requests to open a session with the Trusted Application. The open
 * session request may result in a new Trusted Application instance being
 * created as defined in section 4.5.
 *
 * The client can specify parameters in an open operation which are passed
 * to the Trusted Application instance in the arguments paramTypes and
 * params. These arguments can also be used by the Trusted Application
 * instance to transfer response data back to the client. See section 4.3.6
 * for a specification of how to handle the operation parameters.
 *
 * If this function returns TEE_SUCCESS, the client is connected to a
 * Trusted Application instance and can invoke Trusted Application
 * commands. When the client disconnects, the Framework will eventually
 * call the TA_CloseSessionEntryPoint entry point.
 *
 * If the function returns any error, the Framework rejects the connection
 * and returns the error code and the current content of the parameters the
 * client. The return origin is then set to TEE_ORIGIN_TRUSTED_APP.
 *
 * The Trusted Application instance can register a session data pointer by
 * setting *psessionContext. The value of this pointer is not interpreted
 * by the Framework, and is simply passed back to other TA_ functions
 * within this session. Note that *sessionContext may be set with a pointer
 * to a memory allocated by the Trusted Application instance or with
 * anything else, like an integer, a handle etc. The Framework will not
 * automatically free *sessionContext when the session is closed; the
 * Trusted Application instance is responsible for freeing memory if
 * required.
 *
 * During the call to TA_OpenSessionEntryPoint the client may request to
 * cancel the operation. See section 4.10 for more details on
 * cancellations. If the call to TA_OpenSessionEntryPoint returns
 * TEE_SUCCESS, the client must consider the session as successfully opened
 * and explicitly close it if necessary.
 *
 * Parameters:
 * - paramTypes: the types of the four parameters.
 * - params: a pointer to an array of four parameters.
 * - sessionContext: A pointer to a variable that can be filled by the
 *   Trusted Application instance with an opaque void* data pointer
 *
 * Return Value:
 * - TEE_SUCCESS if the session is successfully opened.
 * - Any other value if the session could not be open.
 *   o The error code may be one of the pre-defined codes, or may be a new
 *     error code defined by the Trusted Application implementation itself.
 */
TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				void **sessionContext);

/*
 * The Framework calls this function to close a client session. During the
 * call to this function the implementation can use any session functions.
 *
 * The Trusted Application implementation is responsible for freeing any
 * resources consumed by the session being closed. Note that the Trusted
 * Application cannot refuse to close a session, but can hold the closing
 * until it returns from TA_CloseSessionEntryPoint. This is why this
 * function cannot return an error code.
 *
 * Parameters:
 * - sessionContext: The value of the void* opaque data pointer set by the
 *   Trusted Application in the function TA_OpenSessionEntryPoint for this
 *   session.
 */
void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext);

/*
 * The Framework calls this function when the client invokes a command
 * within the given session.
 *
 * The Trusted Application can access the parameters sent by the client
 * through the paramTypes and params arguments. It can also use these
 * arguments to transfer response data back to the client.
 *
 * During the call to TA_InvokeCommandEntryPoint the client may request to
 * cancel the operation.
 *
 * A command is always invoked within the context of a client session.
 * Thus, any session function  can be called by the command implementation.
 *
 * Parameter:
 * - sessionContext: The value of the void* opaque data pointer set by the
 *   Trusted Application in the function TA_OpenSessionEntryPoint.
 * - commandID: A Trusted Application-specific code that identifies the
 *   command to be invoked.
 * - paramTypes: the types of the four parameters.
 * - params: a pointer to an array of four parameters.
 *
 * Return Value:
 * - TEE_SUCCESS: if the command is successfully executed, the function
 *   must return this value.
 * - Any other value: if the invocation of the command fails for any
 *   reason.
 *   o The error code may be one of the pre-defined codes, or may be a new
 *     error code defined by the Trusted Application implementation itself.
 */

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
			uint32_t commandID,
			uint32_t paramTypes,
			TEE_Param params[TEE_NUM_PARAMS]);

/*
 * Correspondance Client Functions <--> TA Functions
 *
 * TEE_OpenSession or TEE_OpenTASession:
 * If a new Trusted Application instance is needed to handle the session,
 * TA_CreateEntryPoint is called.
 * Then, TA_OpenSessionEntryPoint is called.
 *
 *
 * TEE_InvokeCommand or TEE_InvokeTACommand:
 * TA_InvokeCommandEntryPoint is called.
 *
 *
 * TEE_CloseSession or TEE_CloseTASession:
 * TA_CloseSessionEntryPoint is called.
 * For a multi-instance TA or for a single-instance, non keep-alive TA, if
 * the session closed was the last session on the instance, then
 * TA_DestroyEntryPoint is called. Otherwise, the instance is kept until
 * the TEE shuts down.
 *
 */

#endif
