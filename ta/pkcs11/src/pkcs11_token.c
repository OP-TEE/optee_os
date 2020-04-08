// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <confine_array_index.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "serializer.h"

/* Provide 3 slots/tokens, ID is token index */
#ifndef CFG_PKCS11_TA_TOKEN_COUNT
#define TOKEN_COUNT		3
#else
#define TOKEN_COUNT		CFG_PKCS11_TA_TOKEN_COUNT
#endif

/*
 * Structure tracking client applications
 *
 * @link - chained list of registered client applications
 * @sessions - list of the PKCS11 sessions opened by the client application
 */
struct pkcs11_client {
	TAILQ_ENTRY(pkcs11_client) link;
	struct session_list session_list;
	struct handle_db session_handle_db;
};

/* Static allocation of tokens runtime instances (reset to 0 at load) */
struct ck_token ck_token[TOKEN_COUNT];

static struct client_list pkcs11_client_list =
	TAILQ_HEAD_INITIALIZER(pkcs11_client_list);

static void close_ck_session(struct pkcs11_session *session);

struct ck_token *get_token(unsigned int token_id)
{
	if (token_id < TOKEN_COUNT)
		return &ck_token[confine_array_index(token_id, TOKEN_COUNT)];

	return NULL;
}

unsigned int get_token_id(struct ck_token *token)
{
	ptrdiff_t id = token - ck_token;

	assert(id >= 0 && id < TOKEN_COUNT);
	return id;
}

struct pkcs11_client *tee_session2client(void *tee_session)
{
	struct pkcs11_client *client = NULL;

	TAILQ_FOREACH(client, &pkcs11_client_list, link)
		if (client == tee_session)
			break;

	return client;
}

struct pkcs11_session *pkcs11_handle2session(uint32_t handle,
					     struct pkcs11_client *client)
{
	return handle_lookup(&client->session_handle_db, handle);
}

struct pkcs11_client *register_client(void)
{
	struct pkcs11_client *client = NULL;

	client = TEE_Malloc(sizeof(*client), TEE_MALLOC_FILL_ZERO);
	if (!client)
		return NULL;

	TAILQ_INSERT_HEAD(&pkcs11_client_list, client, link);
	TAILQ_INIT(&client->session_list);
	handle_db_init(&client->session_handle_db);

	return client;
}

void unregister_client(struct pkcs11_client *client)
{
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *next = NULL;

	if (!client) {
		EMSG("Invalid TEE session handle");
		return;
	}

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next)
		close_ck_session(session);

	TAILQ_REMOVE(&pkcs11_client_list, client, link);
	handle_db_destroy(&client->session_handle_db);
	TEE_Free(client);
}

static TEE_Result pkcs11_token_init(unsigned int id)
{
	struct ck_token *token = init_persistent_db(id);

	if (!token)
		return TEE_ERROR_SECURITY;

	if (token->state == PKCS11_TOKEN_RESET) {
		/* As per PKCS#11 spec, token resets to read/write state */
		token->state = PKCS11_TOKEN_READ_WRITE;
		token->session_count = 0;
		token->rw_session_count = 0;
	}

	return TEE_SUCCESS;
}

TEE_Result pkcs11_init(void)
{
	unsigned int id = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	for (id = 0; id < TOKEN_COUNT; id++) {
		ret = pkcs11_token_init(id);
		if (ret)
			break;
	}

	return ret;
}

void pkcs11_deinit(void)
{
	unsigned int id = 0;

	for (id = 0; id < TOKEN_COUNT; id++)
		close_persistent_db(get_token(id));
}

uint32_t entry_ck_slot_list(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *out = &params[2];
	uint32_t token_id = 0;
	const size_t out_size = sizeof(token_id) * TOKEN_COUNT;
	uint8_t *id = NULL;

	if (ptypes != exp_pt ||
	    params[0].memref.size != TEE_PARAM0_SIZE_MIN)
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;

		if (out->memref.buffer)
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		else
			return PKCS11_CKR_OK;
	}

	for (token_id = 0, id = out->memref.buffer; token_id < TOKEN_COUNT;
	     token_id++, id += sizeof(token_id))
		TEE_MemMove(id, &token_id, sizeof(token_id));

	out->memref.size = out_size;

	return PKCS11_CKR_OK;
}

static void pad_str(uint8_t *str, size_t size)
{
	int n = strnlen((char *)str, size);

	TEE_MemFill(str + n, ' ', size - n);
}

uint32_t entry_ck_slot_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_slot_info info = {
		.slot_description = PKCS11_SLOT_DESCRIPTION,
		.manufacturer_id = PKCS11_SLOT_MANUFACTURER,
		.flags = PKCS11_CKFS_TOKEN_PRESENT,
		.hardware_version = PKCS11_SLOT_HW_VERSION,
		.firmware_version = PKCS11_SLOT_FW_VERSION,
	};

	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_DESCRIPTION) <=
			    sizeof(info.slot_description));
	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_MANUFACTURER) <=
			    sizeof(info.manufacturer_id));

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	pad_str(info.slot_description, sizeof(info.slot_description));
	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, out->memref.size);

	return PKCS11_CKR_OK;
}

uint32_t entry_ck_token_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_token_info info = {
		.manufacturer_id = PKCS11_TOKEN_MANUFACTURER,
		.model = PKCS11_TOKEN_MODEL,
		.serial_number = PKCS11_TOKEN_SERIAL_NUMBER,
		.max_session_count = UINT32_MAX,
		.max_rw_session_count = UINT32_MAX,
		.max_pin_len = PKCS11_TOKEN_PIN_SIZE_MAX,
		.min_pin_len = PKCS11_TOKEN_PIN_SIZE_MIN,
		.total_public_memory = UINT32_MAX,
		.free_public_memory = UINT32_MAX,
		.total_private_memory = UINT32_MAX,
		.free_private_memory = UINT32_MAX,
		.hardware_version = PKCS11_TOKEN_HW_VERSION,
		.firmware_version = PKCS11_TOKEN_FW_VERSION,
	};

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));
	pad_str(info.model, sizeof(info.model));
	pad_str(info.serial_number, sizeof(info.serial_number));

	TEE_MemMove(info.label, token->db_main->label, sizeof(info.label));

	info.flags = token->db_main->flags;
	info.session_count = token->session_count;
	info.rw_session_count = token->rw_session_count;

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return PKCS11_CKR_OK;
}

static void dmsg_print_supported_mechanism(unsigned int token_id __maybe_unused,
					   uint32_t *array __maybe_unused,
					   size_t count __maybe_unused)
{
	size_t __maybe_unused n = 0;

	if (TRACE_LEVEL < TRACE_DEBUG)
		return;

	for (n = 0; n < count; n++)
		DMSG("PKCS11 token %"PRIu32": mechanism 0x%04"PRIx32": %s",
		     token_id, array[n], id2str_mechanism(array[n]));
}

uint32_t entry_ck_token_mecha_ids(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token __maybe_unused *token = NULL;
	size_t count = 0;
	uint32_t *array = NULL;

	if (ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	count = out->memref.size / sizeof(*array);
	array = tee_malloc_mechanism_list(&count);

	if (out->memref.size < count * sizeof(*array)) {
		assert(!array);
		out->memref.size = count * sizeof(*array);
		if (out->memref.buffer)
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		else
			return PKCS11_CKR_OK;
	}

	if (!array)
		return PKCS11_CKR_DEVICE_MEMORY;

	dmsg_print_supported_mechanism(token_id, array, count);

	out->memref.size = count * sizeof(*array);
	TEE_MemMove(out->memref.buffer, array, out->memref.size);

	TEE_Free(array);

	return rv;
}

static void supported_mechanism_key_size(uint32_t proc_id,
					 uint32_t *max_key_size,
					 uint32_t *min_key_size)
{
	switch (proc_id) {
	/* Will be filled once TA supports mechanisms */
	default:
		*min_key_size = 0;
		*max_key_size = 0;
		break;
	}
}

uint32_t entry_ck_token_mecha_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	uint32_t type = 0;
	struct ck_token *token = NULL;
	struct pkcs11_mechanism_info info = { };

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &type, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	if (!mechanism_is_valid(type))
		return PKCS11_CKR_MECHANISM_INVALID;

	info.flags = mechanism_supported_flags(type);

	supported_mechanism_key_size(type, &info.min_key_size,
				     &info.max_key_size);

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	DMSG("PKCS11 token %"PRIu32": mechanism 0x%"PRIx32" info",
	     token_id, type);

	return PKCS11_CKR_OK;
}

/* Select the ReadOnly or ReadWrite state for session login state */
static void set_session_state(struct pkcs11_client *client,
			      struct pkcs11_session *session, bool readonly)
{
	struct pkcs11_session *sess = NULL;
	enum pkcs11_session_state state = PKCS11_CKS_RO_PUBLIC_SESSION;

	/* Default to public session if no session already registered */
	if (readonly)
		state = PKCS11_CKS_RO_PUBLIC_SESSION;
	else
		state = PKCS11_CKS_RW_PUBLIC_SESSION;

	/*
	 * No need to check all client sessions, the first found in
	 * target token gives client login configuration.
	 */
	TAILQ_FOREACH(sess, &client->session_list, link) {
		assert(sess != session);

		if (sess->token == session->token) {
			switch (sess->state) {
			case PKCS11_CKS_RW_PUBLIC_SESSION:
			case PKCS11_CKS_RO_PUBLIC_SESSION:
				if (readonly)
					state = PKCS11_CKS_RO_PUBLIC_SESSION;
				else
					state = PKCS11_CKS_RW_PUBLIC_SESSION;
				break;
			case PKCS11_CKS_RO_USER_FUNCTIONS:
			case PKCS11_CKS_RW_USER_FUNCTIONS:
				if (readonly)
					state = PKCS11_CKS_RO_USER_FUNCTIONS;
				else
					state = PKCS11_CKS_RW_USER_FUNCTIONS;
				break;
			case PKCS11_CKS_RW_SO_FUNCTIONS:
				if (readonly)
					TEE_Panic(0);
				else
					state = PKCS11_CKS_RW_SO_FUNCTIONS;
				break;
			default:
				TEE_Panic(0);
			}
			break;
		}
	}

	session->state = state;
}

uint32_t entry_ck_open_session(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	uint32_t flags = 0;
	struct ck_token *token = NULL;
	struct pkcs11_session *session = NULL;
	bool readonly = false;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(session->handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &flags, sizeof(flags));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	/* Sanitize session flags */
	if (!(flags & PKCS11_CKFSS_SERIAL_SESSION) ||
	    (flags & ~(PKCS11_CKFSS_RW_SESSION |
		       PKCS11_CKFSS_SERIAL_SESSION)))
		return PKCS11_CKR_ARGUMENTS_BAD;

	readonly = !(flags & PKCS11_CKFSS_RW_SESSION);

	if (!readonly && token->state == PKCS11_TOKEN_READ_ONLY)
		return PKCS11_CKR_TOKEN_WRITE_PROTECTED;

	if (readonly) {
		/* Specifically reject read-only session under SO login */
		TAILQ_FOREACH(session, &client->session_list, link)
			if (pkcs11_session_is_so(session))
				return PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

	session = TEE_Malloc(sizeof(*session), TEE_MALLOC_FILL_ZERO);
	if (!session)
		return PKCS11_CKR_DEVICE_MEMORY;

	session->handle = handle_get(&client->session_handle_db, session);
	if (!session->handle) {
		TEE_Free(session);
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	session->token = token;
	session->client = client;

	set_session_state(client, session, readonly);

	TAILQ_INSERT_HEAD(&client->session_list, session, link);

	session->token->session_count++;
	if (!readonly)
		session->token->rw_session_count++;

	TEE_MemMove(out->memref.buffer, &session->handle,
		    sizeof(session->handle));

	DMSG("Open PKCS11 session %"PRIu32, session->handle);

	return PKCS11_CKR_OK;
}

static void close_ck_session(struct pkcs11_session *session)
{
	TAILQ_REMOVE(&session->client->session_list, session, link);
	handle_put(&session->client->session_handle_db, session->handle);

	session->token->session_count--;
	if (pkcs11_session_is_read_write(session))
		session->token->rw_session_count--;

	TEE_Free(session);

	DMSG("Close PKCS11 session %"PRIu32, session->handle);
}

uint32_t entry_ck_close_session(struct pkcs11_client *client,
				uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	close_ck_session(session);

	return PKCS11_CKR_OK;
}

uint32_t entry_ck_close_all_sessions(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *next = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	DMSG("Close all sessions for PKCS11 token %"PRIu32, token_id);

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next)
		if (session->token == token)
			close_ck_session(session);

	return PKCS11_CKR_OK;
}

uint32_t entry_ck_session_info(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	struct pkcs11_session_info info = {
		.flags = PKCS11_CKFSS_SERIAL_SESSION,
	};

	if (!client || ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	info.slot_id = get_token_id(session->token);
	info.state = session->state;
	if (pkcs11_session_is_read_write(session))
		info.flags |= PKCS11_CKFSS_RW_SESSION;

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	DMSG("Get find on PKCS11 session %"PRIu32, session->handle);

	return PKCS11_CKR_OK;
}
