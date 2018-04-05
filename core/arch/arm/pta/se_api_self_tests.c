// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <compiler.h>
#include <kernel/pseudo_ta.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <trace.h>

#include <tee/se/manager.h>
#include <tee/se/reader.h>
#include <tee/se/session.h>
#include <tee/se/iso7816.h>
#include <tee/se/aid.h>
#include <tee/se/apdu.h>
#include <tee/se/channel.h>
#include <tee/se/util.h>

#include <stdlib.h>
#include <string.h>

#include "aid_priv.h"
#include "apdu_priv.h"
#include "reader_priv.h"


#define TA_NAME		"se_api_self_tests.ta"

#define MAX_READERS	10

#define CMD_SELF_TESTS	0

#define SE_API_SELF_TEST_UUID \
		{ 0xAEB79790, 0x6F03, 0x11E4,  \
			{ 0x98, 0x03, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66 } }

#define ASSERT(expr) \
	do { \
		if (!(expr)) { \
			EMSG("assertion '%s' failed at %s:%d (func '%s')", \
				#expr, __FILE__, __LINE__, __func__); \
			return TEE_ERROR_GENERIC; \
		} \
	} while (0)

#define CHECK(ret) \
	do { \
		if (ret != TEE_SUCCESS) \
			return ret; \
	} while (0)

/*
 * Trusted Application Entry Points
 */

static TEE_Result test_reader(struct tee_se_reader_proxy **handle)
{
	TEE_Result ret;
	uint8_t cmd[] = { ISO7816_CLA, MANAGE_CHANNEL_CMD,
		OPEN_CHANNEL, OPEN_NEXT_AVAILABLE };
	uint8_t resp[3];
	size_t resp_size = sizeof(resp);
	const int expected_channel_id = 1;

	DMSG("entry");
	/* transmit should fail since no one attached to the reader */
	ret = tee_se_reader_transmit(handle[0], cmd, sizeof(cmd),
			resp, &resp_size);
	ASSERT(ret == TEE_ERROR_BAD_STATE);

	ret = tee_se_reader_attach(handle[0]);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_reader_attach(handle[0]);
	ASSERT(ret == TEE_SUCCESS);

	/* referenced by 2 owners */
	ASSERT(2 == tee_se_reader_get_refcnt(handle[0]));

	ret = tee_se_reader_transmit(handle[0], cmd, sizeof(cmd),
				resp, &resp_size);
	ASSERT(ret == TEE_SUCCESS);
	ASSERT(resp[0] == expected_channel_id &&
		resp[1] == CMD_OK_SW1 && resp[2] == CMD_OK_SW2);

	tee_se_reader_detach(handle[0]);

	ASSERT(1 == tee_se_reader_get_refcnt(handle[0]));

	tee_se_reader_detach(handle[0]);
	DMSG("exit");

	return TEE_SUCCESS;
}

static TEE_Result test_aid(struct tee_se_reader_proxy **proxies)
{
	struct tee_se_session *s = NULL;
	struct tee_se_channel *b = NULL, *l = NULL;
	struct tee_se_aid *aid = NULL;
	TEE_Result ret;

	DMSG("entry");
	ret = tee_se_aid_create("D0000CAFE00001", &aid);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_reader_open_session(proxies[0], &s);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_session_open_basic_channel(s, aid, &b);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_session_open_logical_channel(s, aid, &l);
	ASSERT(ret == TEE_SUCCESS);

	ASSERT(tee_se_aid_get_refcnt(aid) == 3);

	tee_se_session_close_channel(s, b);
	tee_se_session_close_channel(s, l);

	ASSERT(tee_se_aid_get_refcnt(aid) == 1);

	tee_se_session_close(s);
	tee_se_aid_release(aid);
	DMSG("exit");

	return TEE_SUCCESS;
}

static TEE_Result test_session(struct tee_se_reader_proxy **proxies)
{
	struct tee_se_channel *c1 = NULL, *c2 = NULL;
	struct tee_se_session *s1 = NULL, *s2 = NULL;
	TEE_Result ret;

	DMSG("entry");
	ret = tee_se_reader_open_session(proxies[0], &s1);
	ASSERT(ret == TEE_SUCCESS);

	/* should success, multiple sessions open by different user */
	ret = tee_se_reader_open_session(proxies[0], &s2);
	ASSERT(ret == TEE_SUCCESS);

	/* open basic channel on s1 (should success) */
	ret = tee_se_session_open_basic_channel(s1, NULL, &c1);
	ASSERT(ret == TEE_SUCCESS);

	/* open basic channel on s2
	 * (should fail, basic channel is locked by s1)
	 */
	ret = tee_se_session_open_basic_channel(s2, NULL, &c2);
	ASSERT(ret == TEE_ERROR_NOT_SUPPORTED);
	ASSERT(c2 == NULL);

	/* close basic channel on s1 */
	tee_se_session_close_channel(s1, c1);
	c1 = NULL;

	/* open basic channel on s2 (this time should success) */
	ret = tee_se_session_open_basic_channel(s1, NULL, &c2);
	ASSERT(ret == TEE_SUCCESS);

	/* close basic channel on s2 */
	tee_se_session_close_channel(s2, c2);
	c2 = NULL;

	/* open logical channel on s1 and s2 (both should success) */
	ret = tee_se_session_open_logical_channel(s1, NULL, &c1);
	ASSERT(ret == TEE_SUCCESS);
	ret = tee_se_session_open_logical_channel(s2, NULL, &c2);
	ASSERT(ret == TEE_SUCCESS);

	/* clean up */
	tee_se_session_close_channel(s1, c1);
	tee_se_session_close_channel(s2, c2);

	tee_se_session_close(s1);
	tee_se_session_close(s2);
	DMSG("exit");

	return TEE_SUCCESS;
}

static TEE_Result test_select_resp(struct tee_se_reader_proxy **proxies)
{
	struct tee_se_aid *aid = NULL;
	struct tee_se_session *s = NULL;
	struct tee_se_channel *c = NULL;
	struct resp_apdu *resp;
	TEE_Result ret;

	DMSG("entry");
	ret = tee_se_aid_create("D0000CAFE00001", &aid);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_reader_open_session(proxies[0], &s);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_session_open_logical_channel(s, aid, &c);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_channel_get_select_response(c, &resp);
	ASSERT(ret == TEE_SUCCESS);

	ASSERT((resp_apdu_get_sw1(resp) == CMD_OK_SW1) &&
			(resp_apdu_get_sw2(resp) == CMD_OK_SW2));

	/*
	 * the ownership of resp apdu should be the channel
	 * and it should be the only owner
	 */
	ASSERT(apdu_get_refcnt(to_apdu_base(resp)) == 1);

	/* increase the reference counter of resp apdu */
	apdu_acquire(to_apdu_base(resp));

	/* clean up */
	tee_se_session_close_channel(s, c);

	/* channel should release resp apdu when closed */
	ASSERT(apdu_get_refcnt(to_apdu_base(resp)) == 1);
	apdu_release(to_apdu_base(resp));

	tee_se_session_close(s);
	tee_se_aid_release(aid);
	DMSG("exit");

	return TEE_SUCCESS;
}

/*
 * The JAVA Card Simulator (jcardsim.jar) built-in applet(s):
 *
 * AID					|Type
 * -------------------------------------+----------------------
 * D0000CAFE00001			| MultiSelectable
 * (default selected on basic channel)	|
 * -------------------------------------+----------------------
 * D0000CAFE00002			| Non-MultiSelectable
 * -------------------------------------+----------------------
 *
 */
static TEE_Result test_logical_channel(struct tee_se_reader_proxy **proxies)
{
	struct tee_se_channel *channel[MAX_LOGICAL_CHANNEL] = { NULL };
	struct tee_se_aid *aid = NULL;
	struct tee_se_session *s = NULL;
	TEE_Result ret;
	int i;

	DMSG("entry");
	ret = tee_se_reader_open_session(proxies[0], &s);
	ASSERT(ret == TEE_SUCCESS);

	/*
	 * test open logical channels based on AID selected on basic channel
	 * (D0000CAFE00001 is default selected on basic channel,
	 * this call should success since D0000CAFE00001 is MultiSelectable,
	 * upon open, each logical channel should select D0000CAFE00001)
	 */
	for (i = 1; i < MAX_LOGICAL_CHANNEL; i ++) {
		ret = tee_se_session_open_logical_channel(s, NULL, &channel[i]);
		ASSERT(ret == TEE_SUCCESS);
	}

	/*
	 * should fail on next open
	 * (exceeds maximum logical channel number)
	 */
	ret = tee_se_session_open_logical_channel(s, NULL, &channel[0]);
	ASSERT(ret == TEE_ERROR_NOT_SUPPORTED);

	/* close 3 channels */
	for (i = 1; i < 4; i++) {
		tee_se_session_close_channel(s, channel[i]);
		channel[i] = NULL;
	}

	/* re-open 3 channels (should success) */
	for (i = 1; i < 4; i++) {
		ret = tee_se_session_open_logical_channel(s, NULL, &channel[i]);
		ASSERT(ret == TEE_SUCCESS);
	}

	/* logical channel 1 select D0000CAFE00002 (should success) */
	tee_se_aid_create("D0000CAFE00002", &aid);
	ret = tee_se_channel_select(channel[1], aid);
	ASSERT(ret == TEE_SUCCESS);

	/* logical channel 2 select D0000CAFE00002
	 * (should fail since D0000CAFE00002 is not MultiSelectable)
	 */
	ret = tee_se_channel_select(channel[2], aid);
	ASSERT(ret == TEE_ERROR_NOT_SUPPORTED);

	/* clean up */
	for (i = 1; i < MAX_LOGICAL_CHANNEL; i++)
		tee_se_session_close_channel(s, channel[i]);
	tee_se_session_close(s);
	tee_se_aid_release(aid);
	DMSG("exit");

	return TEE_SUCCESS;
}

static TEE_Result verify_result(struct resp_apdu *apdu, const char *data)
{
	size_t str_length = strlen(data);
	size_t byte_length = strlen(data) / 2;
	uint8_t *resp_data = resp_apdu_get_data(apdu);
	size_t resp_len = resp_apdu_get_data_len(apdu);
	uint8_t bytes[byte_length];
	size_t i = 0;

	ASSERT(resp_len == byte_length);

	hex_decode(data, str_length, bytes);
	while (i < resp_len) {
		ASSERT(bytes[i] == resp_data[i]);
		i++;
	}
	return TEE_SUCCESS;
}

static TEE_Result test_transmit(struct tee_se_reader_proxy **proxies)
{
	struct tee_se_channel *c1 = NULL, *c2 = NULL;
	struct tee_se_session *s1 = NULL, *s2 = NULL;
	struct tee_se_aid *full_aid = NULL, *partial_aid = NULL;
	struct cmd_apdu *cmd;
	struct resp_apdu *resp;
	size_t tx_buf_len = 0, rx_buf_len = 7;
	TEE_Result ret;

	DMSG("entry");
	ret = tee_se_aid_create("D0000CAFE00001", &full_aid);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_aid_create("D0000CAFE0000", &partial_aid);
	ASSERT(ret == TEE_SUCCESS);

	cmd = alloc_cmd_apdu(ISO7816_CLA, 0xFF, 0x0, 0x0,
			tx_buf_len, rx_buf_len, NULL);
	ASSERT(cmd);
	resp = alloc_resp_apdu(rx_buf_len);
	ASSERT(resp);

	ret = tee_se_reader_open_session(proxies[0], &s1);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_reader_open_session(proxies[0], &s2);
	ASSERT(ret == TEE_SUCCESS);

	/* open logical channel on s1 (given full aid) */
	ret = tee_se_session_open_logical_channel(s1, full_aid, &c1);
	ASSERT(ret == TEE_SUCCESS);

	/* should route to D0000CAFE00001 */
	ret = tee_se_channel_transmit(c1, cmd, resp);
	ASSERT(ret == TEE_SUCCESS);

	/* select next should fail (full aid given) */
	ret = tee_se_channel_select_next(c1);
	ASSERT(ret == TEE_ERROR_ITEM_NOT_FOUND);

	/* open logical channel on s2 (given partial aid) */
	ret = tee_se_session_open_logical_channel(s2, partial_aid, &c2);
	ASSERT(ret == TEE_SUCCESS);

	/* should route to D0000CAFE00001 */
	ret = tee_se_channel_transmit(c2, cmd, resp);
	ASSERT(ret == TEE_SUCCESS);
	ret = verify_result(resp, "D0000CAFE00001");
	ASSERT(ret == TEE_SUCCESS);

	/* select next should success (select D0000CAFE00002) */
	ret = tee_se_channel_select_next(c2);
	ASSERT(ret == TEE_SUCCESS);

	/* should route to D0000CAFE00002 */
	ret = tee_se_channel_transmit(c2, cmd, resp);
	ASSERT(ret == TEE_SUCCESS);
	ret = verify_result(resp, "D0000CAFE00002");
	ASSERT(ret == TEE_SUCCESS);

	/* select next should success (select D0000CAFE00001) */
	ret = tee_se_channel_select_next(c2);
	ASSERT(ret == TEE_SUCCESS);

	/* should route to D0000CAFE00001 */
	ret = tee_se_channel_transmit(c2, cmd, resp);
	ASSERT(ret == TEE_SUCCESS);
	ret = verify_result(resp, "D0000CAFE00001");
	ASSERT(ret == TEE_SUCCESS);

	/*
	 * test route to the same applet in a row from different channel
	 * (both should success)
	 */
	ret = tee_se_channel_transmit(c1, cmd, resp);
	ASSERT(ret == TEE_SUCCESS);
	ret = verify_result(resp, "D0000CAFE00001");
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_channel_transmit(c2, cmd, resp);
	ASSERT(ret == TEE_SUCCESS);
	ret = verify_result(resp, "D0000CAFE00001");
	ASSERT(ret == TEE_SUCCESS);

	/* clean up */
	tee_se_session_close_channel(s1, c1);
	tee_se_session_close_channel(s2, c2);

	tee_se_session_close(s1);
	tee_se_session_close(s2);

	tee_se_aid_release(full_aid);
	tee_se_aid_release(partial_aid);
	DMSG("exit");

	return TEE_SUCCESS;
}

static TEE_Result se_api_self_tests(uint32_t nParamTypes __unused,
				    TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	size_t size = MAX_READERS;
	TEE_Result ret;
	struct tee_se_reader_proxy **proxies =
		malloc(sizeof(void *) * MAX_READERS);

	tee_se_manager_get_readers(proxies, &size);

	ret = test_aid(proxies);
	CHECK(ret);

	ret = test_select_resp(proxies);
	CHECK(ret);

	ret = test_session(proxies);
	CHECK(ret);

	ret = test_logical_channel(proxies);
	CHECK(ret);

	ret = test_transmit(proxies);
	CHECK(ret);

	ret = test_reader(proxies);
	CHECK(ret);

	free(proxies);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID, uint32_t nParamTypes,
		TEE_Param pParams[TEE_NUM_PARAMS])
{
	DMSG("command entry point for pseudo TA \"%s\"", TA_NAME);

	switch (nCommandID) {
	case CMD_SELF_TESTS:
		return se_api_self_tests(nParamTypes, pParams);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = SE_API_SELF_TEST_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
