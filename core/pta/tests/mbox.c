// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, STMicroelectronics
 */
#include <drivers/mailbox.h>
#include <config.h>
#include <drivers/mailbox_controller.h>
#include <inttypes.h>
#include <kernel/mutex.h>
#include <pta_invoke_tests.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "mbox_test.h"
#include "mbox_virt.h"

#define MBOX_TEST_MSG(...)	EMSG("(mailbox-test) " __VA_ARGS__)

/* Check an API result against the expected one, abort the test case if not */
#define EXPECT_RES(_expr, _expected) \
	do { \
		TEE_Result __res = (_expr); \
		if (__res != (_expected)) { \
			MBOX_TEST_MSG("%s:%d: expected %#" PRIx32 ", got %#" \
				      PRIx32, __func__, __LINE__, \
				      (uint32_t)(_expected), (uint32_t)__res); \
			return TEE_ERROR_GENERIC; \
		} \
	} while (0)

#define EXPECT_TRUE(_cond) \
	do { \
		if (!(_cond)) { \
			MBOX_TEST_MSG("%s:%d: check failed: %s", __func__, \
				      __LINE__, #_cond); \
			return TEE_ERROR_GENERIC; \
		} \
	} while (0)

struct mbox_test_case {
	const char *name;
	unsigned int group;
	TEE_Result (*run)(void);
};

static const struct mbox_virt_msg tx_msg = {
	.data = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 },
};

/* Get a fresh controller of @flavor and its channel 0 */
static TEE_Result get_chan(enum mbox_virt_flavor flavor,
			   struct mbox_controller **ctrl,
			   struct mbox_chan **chan)
{
	TEE_Result res = mbox_virt_get(flavor, ctrl);

	if (res)
		return res;

	mbox_virt_reset(*ctrl);

	return mbox_request_channel(*ctrl, NULL, 0, chan);
}

/*
 * Controller registration
 */

static TEE_Result test_register_bad_desc(void)
{
	struct mbox_controller_desc desc = { };
	struct mbox_controller *ctrl = NULL;

	EXPECT_RES(mbox_controller_register(&ctrl, NULL),
		   TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_controller_register(&ctrl, &desc),
		   TEE_ERROR_BAD_PARAMETERS);

	return TEE_SUCCESS;
}

static TEE_Result test_register_missing_mandatory_ops(void)
{
	struct mbox_controller_desc desc = { };
	struct mbox_controller_ops ops = { };
	struct mbox_controller *ctrl = NULL;

	desc.ops = &ops;

	/* No request_channel and no send_sync */
	EXPECT_RES(mbox_controller_register(&ctrl, &desc),
		   TEE_ERROR_BAD_PARAMETERS);

	ops.request_channel = (void *)test_register_missing_mandatory_ops;
	EXPECT_RES(mbox_controller_register(&ctrl, &desc),
		   TEE_ERROR_BAD_PARAMETERS);

	ops.request_channel = NULL;
	ops.send_sync = (void *)test_register_missing_mandatory_ops;
	EXPECT_RES(mbox_controller_register(&ctrl, &desc),
		   TEE_ERROR_BAD_PARAMETERS);

	return TEE_SUCCESS;
}

static TEE_Result test_register_optional_ops(void)
{
	struct mbox_controller *ctrl = NULL;

	/* recv_sync and free_channel are optional */
	EXPECT_RES(mbox_virt_get(MBOX_VIRT_NO_RECV, &ctrl), TEE_SUCCESS);
	EXPECT_TRUE(ctrl);
	EXPECT_RES(mbox_virt_get(MBOX_VIRT_NO_FREE, &ctrl), TEE_SUCCESS);
	EXPECT_TRUE(ctrl);

	return TEE_SUCCESS;
}

/*
 * Channel request and release
 */

static TEE_Result test_channel_request(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_chan *chan1 = NULL;
	struct mbox_virt_stats *stats = NULL;
	uint32_t args[] = { 1 };

	EXPECT_RES(mbox_virt_get(MBOX_VIRT_FULL, &ctrl), TEE_SUCCESS);
	mbox_virt_reset(ctrl);
	stats = mbox_virt_stats(ctrl);

	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &chan), TEE_SUCCESS);
	EXPECT_TRUE(chan && chan->controller == ctrl);
	EXPECT_TRUE(stats->requested == 1 && !stats->last_args_count);

	EXPECT_RES(mbox_request_channel(ctrl, args, ARRAY_SIZE(args), &chan1),
		   TEE_SUCCESS);
	EXPECT_TRUE(chan1 && chan1 != chan && chan1->controller == ctrl);
	EXPECT_TRUE(stats->last_args_count == ARRAY_SIZE(args));
	EXPECT_TRUE(stats->last_arg0 == args[0]);

	mbox_free_channel(chan);
	mbox_free_channel(chan1);

	return TEE_SUCCESS;
}

static TEE_Result test_channel_exclusive(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_chan *other = NULL;
	struct mbox_virt_stats *stats = NULL;

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);
	stats = mbox_virt_stats(ctrl);

	/* A granted channel cannot be requested again */
	other = chan;
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &other),
		   TEE_ERROR_BUSY);
	EXPECT_TRUE(!other);
	EXPECT_TRUE(stats->requested == 2 && !stats->freed);

	/* Once released, it can be requested again */
	mbox_free_channel(chan);
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &other), TEE_SUCCESS);
	EXPECT_TRUE(other == chan);
	mbox_free_channel(other);

	return TEE_SUCCESS;
}

static TEE_Result test_channel_request_bad_params(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_stats *stats = NULL;

	EXPECT_RES(mbox_virt_get(MBOX_VIRT_FULL, &ctrl), TEE_SUCCESS);
	mbox_virt_reset(ctrl);
	stats = mbox_virt_stats(ctrl);

	EXPECT_RES(mbox_request_channel(NULL, NULL, 0, &chan),
		   TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, NULL),
		   TEE_ERROR_BAD_PARAMETERS);
	/* Specifier cells announced but no specifier */
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 1, &chan),
		   TEE_ERROR_BAD_PARAMETERS);
	/* The driver must not have been reached */
	EXPECT_TRUE(!stats->requested);

	return TEE_SUCCESS;
}

static TEE_Result test_channel_request_invalid_result(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_chan sentinel = { };

	/* The driver reports success but returns no channel */
	EXPECT_RES(mbox_virt_get(MBOX_VIRT_NULL_CHAN, &ctrl), TEE_SUCCESS);
	chan = &sentinel;
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &chan),
		   TEE_ERROR_BAD_STATE);
	EXPECT_TRUE(!chan);

	return TEE_SUCCESS;
}

static TEE_Result test_channel_request_driver_error(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_chan sentinel = { };

	EXPECT_RES(mbox_virt_get(MBOX_VIRT_FAILING, &ctrl), TEE_SUCCESS);
	mbox_virt_reset(ctrl);
	mbox_virt_set_error(ctrl, TEE_ERROR_ITEM_NOT_FOUND);

	chan = &sentinel;
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &chan),
		   TEE_ERROR_ITEM_NOT_FOUND);
	EXPECT_TRUE(!chan);
	mbox_virt_reset(ctrl);

	return TEE_SUCCESS;
}

static TEE_Result test_channel_free(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_chan invalid = { };
	struct mbox_virt_stats *stats = NULL;

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);
	stats = mbox_virt_stats(ctrl);

	mbox_free_channel(chan);
	EXPECT_TRUE(stats->freed == 1);

	/* A channel no longer granted is not released again */
	mbox_free_channel(chan);
	EXPECT_TRUE(stats->freed == 1);

	/* Invalid handles are ignored */
	mbox_free_channel(NULL);
	mbox_free_channel(&invalid);
	EXPECT_TRUE(stats->freed == 1);

	/* free_channel is optional */
	EXPECT_RES(get_chan(MBOX_VIRT_NO_FREE, &ctrl, &chan), TEE_SUCCESS);
	mbox_free_channel(chan);

	return TEE_SUCCESS;
}

/*
 * Synchronous send and receive
 */

static TEE_Result test_sync_send_recv(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;
	struct mbox_virt_msg rx = { };
	struct mbox_virt_stats *stats = NULL;

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);
	stats = mbox_virt_stats(ctrl);

	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_SUCCESS);
	EXPECT_RES(mbox_recv_sync(chan, &rx), TEE_SUCCESS);
	EXPECT_TRUE(!memcmp(&rx, &tx_msg, sizeof(rx)));
	EXPECT_TRUE(stats->sent == 1 && stats->received == 1);

	return TEE_SUCCESS;
}

static TEE_Result test_sync_recv_then_send(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;
	struct mbox_virt_msg rx = { };

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);

	/* Nothing to receive yet */
	EXPECT_RES(mbox_recv_sync(chan, &rx), TEE_ERROR_NO_DATA);

	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_SUCCESS);
	EXPECT_RES(mbox_recv_sync(chan, &rx), TEE_SUCCESS);
	EXPECT_TRUE(!memcmp(&rx, &tx_msg, sizeof(rx)));

	/* The message is consumed */
	EXPECT_RES(mbox_recv_sync(chan, &rx), TEE_ERROR_NO_DATA);

	return TEE_SUCCESS;
}

static TEE_Result test_sync_send_busy(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;
	struct mbox_virt_msg rx = { };

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);

	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_SUCCESS);
	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_ERROR_BUSY);
	EXPECT_RES(mbox_recv_sync(chan, &rx), TEE_SUCCESS);
	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_SUCCESS);

	return TEE_SUCCESS;
}

static TEE_Result test_sync_bad_params(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_chan invalid = { };
	struct mbox_virt_msg msg = tx_msg;
	struct mbox_virt_stats *stats = NULL;

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);
	stats = mbox_virt_stats(ctrl);

	EXPECT_RES(mbox_send_sync(NULL, &msg), TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_send_sync(chan, NULL), TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_send_sync(&invalid, &msg), TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_recv_sync(NULL, &msg), TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_recv_sync(chan, NULL), TEE_ERROR_BAD_PARAMETERS);
	EXPECT_RES(mbox_recv_sync(&invalid, &msg), TEE_ERROR_BAD_PARAMETERS);

	/* The driver must not have been reached */
	EXPECT_TRUE(!stats->sent && !stats->received);

	return TEE_SUCCESS;
}

static TEE_Result test_sync_not_requested(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;
	struct mbox_virt_stats *stats = NULL;

	EXPECT_RES(get_chan(MBOX_VIRT_FULL, &ctrl, &chan), TEE_SUCCESS);
	stats = mbox_virt_stats(ctrl);

	/* A released channel is no longer usable */
	mbox_free_channel(chan);
	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_ERROR_BAD_STATE);
	EXPECT_RES(mbox_recv_sync(chan, &msg), TEE_ERROR_BAD_STATE);
	EXPECT_TRUE(!stats->sent && !stats->received);

	/* It is usable again once requested */
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &chan), TEE_SUCCESS);
	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_SUCCESS);
	EXPECT_TRUE(stats->sent == 1);

	return TEE_SUCCESS;
}

static TEE_Result test_sync_recv_not_supported(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;

	EXPECT_RES(get_chan(MBOX_VIRT_NO_RECV, &ctrl, &chan), TEE_SUCCESS);

	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_SUCCESS);
	EXPECT_RES(mbox_recv_sync(chan, &msg), TEE_ERROR_NOT_SUPPORTED);

	return TEE_SUCCESS;
}

static TEE_Result test_sync_driver_error(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;

	EXPECT_RES(mbox_virt_get(MBOX_VIRT_FAILING, &ctrl), TEE_SUCCESS);
	mbox_virt_reset(ctrl);
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &chan), TEE_SUCCESS);

	mbox_virt_set_error(ctrl, TEE_ERROR_TIMEOUT);
	EXPECT_RES(mbox_send_sync(chan, &msg), TEE_ERROR_TIMEOUT);
	EXPECT_RES(mbox_recv_sync(chan, &msg), TEE_ERROR_TIMEOUT);
	mbox_virt_reset(ctrl);

	return TEE_SUCCESS;
}

/*
 * Blocking receive: the two following functions are invoked concurrently, the
 * receiver may be started first or after the sender.
 */

static TEE_Result test_block_recv(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg rx = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	/* The receiver uses channel 0 */
	EXPECT_RES(mbox_virt_get(MBOX_VIRT_BLOCKING, &ctrl), TEE_SUCCESS);
	EXPECT_RES(mbox_request_channel(ctrl, NULL, 0, &chan), TEE_SUCCESS);

	res = mbox_recv_sync(chan, &rx);
	mbox_free_channel(chan);

	EXPECT_RES(res, TEE_SUCCESS);
	EXPECT_TRUE(!memcmp(&rx, &tx_msg, sizeof(rx)));

	return TEE_SUCCESS;
}

static TEE_Result test_block_send(void)
{
	struct mbox_controller *ctrl = NULL;
	struct mbox_chan *chan = NULL;
	struct mbox_virt_msg msg = tx_msg;
	uint32_t args[] = { 1 };
	TEE_Result res = TEE_ERROR_GENERIC;

	/* The sender uses channel 1 */
	EXPECT_RES(mbox_virt_get(MBOX_VIRT_BLOCKING, &ctrl), TEE_SUCCESS);
	EXPECT_RES(mbox_request_channel(ctrl, args, ARRAY_SIZE(args), &chan),
		   TEE_SUCCESS);

	res = mbox_send_sync(chan, &msg);
	mbox_free_channel(chan);

	EXPECT_RES(res, TEE_SUCCESS);

	return TEE_SUCCESS;
}

static const struct mbox_test_case test_cases[] = {
#define TEST_CASE(_group, _fn) { .name = #_fn, .group = _group, .run = _fn }
	TEST_CASE(PTA_MBOX_TEST_REGISTER, test_register_bad_desc),
	TEST_CASE(PTA_MBOX_TEST_REGISTER,
		  test_register_missing_mandatory_ops),
	TEST_CASE(PTA_MBOX_TEST_REGISTER, test_register_optional_ops),
	TEST_CASE(PTA_MBOX_TEST_CHANNEL, test_channel_request),
	TEST_CASE(PTA_MBOX_TEST_CHANNEL, test_channel_exclusive),
	TEST_CASE(PTA_MBOX_TEST_CHANNEL, test_channel_request_bad_params),
	TEST_CASE(PTA_MBOX_TEST_CHANNEL, test_channel_request_invalid_result),
	TEST_CASE(PTA_MBOX_TEST_CHANNEL, test_channel_request_driver_error),
	TEST_CASE(PTA_MBOX_TEST_CHANNEL, test_channel_free),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_send_recv),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_recv_then_send),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_send_busy),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_bad_params),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_not_requested),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_recv_not_supported),
	TEST_CASE(PTA_MBOX_TEST_SYNC, test_sync_driver_error),
#undef TEST_CASE
};

static struct mutex test_mutex = MUTEX_INITIALIZER;

/* Exported entrypoint for mbox tests */
TEE_Result core_mbox_tests(uint32_t ptypes,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int failed = 0;
	unsigned int run = 0;
	uint32_t group = 0;
	size_t n = 0;

	if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		MBOX_TEST_MSG("bad parameters types: 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	group = params[0].value.a;
	if (group == PTA_MBOX_TEST_BLOCK_RECV ||
	    group == PTA_MBOX_TEST_BLOCK_SEND) {
		if (!IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			return TEE_ERROR_NOT_SUPPORTED;

		/* Not under test_mutex, both sides run at the same time */
		if (group == PTA_MBOX_TEST_BLOCK_RECV)
			return test_block_recv();
		return test_block_send();
	}

	if (group > PTA_MBOX_TEST_SYNC)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&test_mutex);
	for (n = 0; n < ARRAY_SIZE(test_cases); n++) {
		if (group != PTA_MBOX_TEST_ALL && group != test_cases[n].group)
			continue;

		run++;
		res = test_cases[n].run();
		if (res) {
			failed++;
			MBOX_TEST_MSG("%s: KO", test_cases[n].name);
		} else {
			MBOX_TEST_MSG("%s: OK", test_cases[n].name);
		}
	}
	mutex_unlock(&test_mutex);

	MBOX_TEST_MSG("%u test(s) run, %u failed", run, failed);

	return failed ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}
