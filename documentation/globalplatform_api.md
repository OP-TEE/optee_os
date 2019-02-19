GlobalPlatform API and OP-TEE
=============================

Contents :

1. Introduction
2. TEE Client API
3. TEE Internal API

# 1. Introduction
[GlobalPlatform](http://www.globalplatform.org) works across industries to
identify, develop and publish specifications which facilitate the secure and
interoperable deployment and management of multiple embedded applications on
secure chip technology. OP-TEE has support for GlobalPlatform [TEE Client API
Specification v1.0](http://www.globalplatform.org/specificationsdevice.asp) and
[TEE Internal Core API Specification v1.1](http://www.globalplatform.org/specificationsdevice.asp).

# 2. TEE Client API
The TEE Client API describes and defines how a client running in a rich
operating environment (REE) should communicate with the TEE. To identify a
Trusted Application (TA) to be used, the client provides an
[UUID](http://en.wikipedia.org/wiki/Universally_unique_identifier). All TA's
exposes one or several functions. Those functions correspond to a so called
`commandID` which also is sent by the client. 

### TEE Contexts
The TEE Context is used for creating a logical connection between the client and
the TEE. The context must be initialized before the TEE Session can be
created. When the client has completed a job running in secure world, it should
finalize the context and thereby also release resources.

### TEE Sessions
Sessions are used to create logical connections between a client and a specific
Trusted Application. When the session has been established the client has
opened up the communication channel towards the specified Trusted Application
identified by the `UUID`. At this stage the client and the Trusted Application
can start to exchange data.


### TEE Client API example / usage
Below you will find the main functions as defined by GlobalPlatform and used
in the communication between the client and the TEE.

#### TEE Functions
``` c
TEEC_Result TEEC_InitializeContext(
	const char* name,
	TEEC_Context* context)

void TEEC_FinalizeContext(
	TEEC_Context* context)

TEEC_Result TEEC_OpenSession (
	TEEC_Context* context,
	TEEC_Session* session,
	const TEEC_UUID* destination,
	uint32_t connectionMethod,
	const void* connectionData,
	TEEC_Operation* operation,
	uint32_t* returnOrigin)

void TEEC_CloseSession (
	TEEC_Session* session)

TEEC_Result TEEC_InvokeCommand(
	TEEC_Session* session,
	uint32_t commandID,
	TEEC_Operation* operation,
	uint32_t* returnOrigin)
```

In principle the commands are called in this order:

	TEEC_InitializeContext(...)
	TEEC_OpenSession(...)
	TEEC_InvokeCommand(...)
	TEEC_CloseSession(...)
	TEEC_FinalizeContext(...)

It is not uncommon that `TEEC_InvokeCommand` is called several times in a row
when the session has been established.

For a complete example, please see chapter **5.2 Example 1: Using the TEE
Client API** in the GlobalPlatform [TEE Client API
Specification v1.0](http://www.globalplatform.org/specificationsdevice.asp).


# 3. TEE Internal API
The Internal API is the API that is exposed to the Trusted Applications running
in the secure world. The TEE Internal API consists of four major parts:

1. **Trusted Storage API for Data and Keys**
2. **Cryptographic Operations API**
3. **Time API**
4. **Arithmetical API**

### Examples / usage
Calling the Internal Core API is done in the same way as described above using Client API.
The best place to find information how this should be done is in the
[TEE Internal Core API Specification
v1.1](http://www.globalplatform.org/specificationsdevice.asp) which contains a
lot of examples of how to call the various APIs.

One can also have a look at the OP-TEE examples git repository
[optee_examples](https://github.com/linaro-swg/optee_examples) documentation.
