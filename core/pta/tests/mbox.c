// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, STMicroelectronics
 */
#include <assert.h>
#include <atomic.h>
#include <config.h>
#include <drivers/mailbox.h>
#include <drivers/mailbox_device.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_time.h>
#include <pta_invoke_tests.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#include "mbox_test.h"

/*
 * Enable expect MBOX_TEST_MSG macro to enable/disable self tests traces.
 *
 * #define MBOX_TEST_MSG     MBOX_TEST_MSG_RAW
 * #define MBOX_TEST_MSG(...)
 */
#define MBOX_TEST_MSG(...)	EMSG("(mailbox-test) " __VA_ARGS__)

#define VIRT_CHAN_NUM 2
#define VIRT_CHAN_SIZE 8

struct virt_mbx_data {
	/* Lock to protect concurrent access */
	unsigned int lock;
	bool enabled;
	/*
	 * Array tx_full and rx_full are used as boolean, since they require
	 * atomic access, they are defined as int to be able to use
	 * atomic_load_int , atomic_store_int
	 */
	int tx_full;
	int rx_full;

	/* Handle for test */
	struct mbox_chan handle;
	/* Copro thread status */
	bool thread;
	/* Count of consumer callbacks called by the mailbox framework */
	unsigned int rx_cb_count;
	unsigned int tx_cb_count;
	uint8_t tx_data[VIRT_CHAN_SIZE];
	uint8_t rx_data[VIRT_CHAN_SIZE];
	char name[4];
	bool used;
};

#define CHAN_TX_NAME "TX" /* tx initiated by target */
#define CHAN_RX_NAME "RX" /* tx initited by copro */

/* Bounds of the active waits between the consumer and the copro threads */
#define CHAN_WAIT_TIMEOUT_MS	1000
#define CHAN_POLL_PERIOD_MS	1

struct virt_mbx_data *virt_mbox_data_tx;
struct virt_mbx_data *virt_mbox_data_rx;

static bool chan_is_enabled(struct virt_mbx_data *data)
{
	uint32_t except = 0;
	bool enabled = false;

	except = cpu_spin_lock_xsave(&data->lock);
	enabled = data->enabled;
	cpu_spin_unlock_xrestore(&data->lock, except);

	return enabled;
}

/*
 * Wait for the consumer side to register its channel. The copro side of the
 * test may be started before the consumer one, hence polling here instead of
 * failing removes any need for the caller to sequence both execution threads.
 */
static TEE_Result wait_chan_enabled(struct virt_mbx_data *data)
{
	unsigned int retries = CHAN_WAIT_TIMEOUT_MS / CHAN_POLL_PERIOD_MS;

	while (!chan_is_enabled(data)) {
		if (!retries) {
			MBOX_TEST_MSG("Channel %s not enabled by consumer",
				      data->name);
			return TEE_ERROR_BAD_STATE;
		}
		retries--;
		tee_time_wait(CHAN_POLL_PERIOD_MS);
	}

	return TEE_SUCCESS;
}

/*
 * Wait for a FIFO state flag to reach @value. Bounded so that a peer thread
 * which never shows up turns into a test failure instead of hanging the
 * calling thread for good.
 */
static TEE_Result wait_fifo_state(struct virt_mbx_data *data __unused,
				  int *flag, int value,
				  const char *what __unused)
{
	unsigned int retries = CHAN_WAIT_TIMEOUT_MS / CHAN_POLL_PERIOD_MS;

	while (atomic_load_int(flag) != value) {
		if (!retries) {
			MBOX_TEST_MSG("Channel %s: timeout waiting for %s",
				      data->name, what);
			return TEE_ERROR_BUSY;
		}
		retries--;
		tee_time_wait(CHAN_POLL_PERIOD_MS);
	}

	return TEE_SUCCESS;
}

static TEE_Result thread_test_recv(struct virt_mbx_data *data,
				   bool reply, int count)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t except = 0;

	if (count > 1 && !reply)
		return TEE_ERROR_BAD_PARAMETERS;

	res = wait_chan_enabled(data);
	if (res)
		return res;

	except = cpu_spin_lock_xsave(&data->lock);
	if (data->thread) {
		cpu_spin_unlock_xrestore(&data->lock, except);
		return TEE_ERROR_BUSY;
	}
	data->thread = true;
	cpu_spin_unlock_xrestore(&data->lock, except);

	/* Wait till a message is sent */
	MBOX_TEST_MSG("th_recv : Start");
	while (count > 0) {
		MBOX_TEST_MSG("th_recv : wait fifo tx full");
		res = wait_fifo_state(data, &data->tx_full, 1, "tx full");
		if (res)
			goto out;

		except = cpu_spin_lock_xsave(&data->lock);
		if (reply) {
			/* Ping pong, recopy received data */
			MBOX_TEST_MSG("th_recv : check fifo rx empty");
			if (atomic_load_int(&data->rx_full)) {
				cpu_spin_unlock_xrestore(&data->lock, except);
				MBOX_TEST_MSG("rx channel = %s is already full",
					      data->name);
				res = TEE_ERROR_BUSY;
				goto out;
			}
			memcpy(data->rx_data, data->tx_data,
			       sizeof(data->rx_data));
			atomic_store_int(&data->rx_full, 1);
		}
		/* Clean tx data */
		memset(data->tx_data, 0xca, sizeof(data->tx_data));
		atomic_store_int(&data->tx_full, 0);
		cpu_spin_unlock_xrestore(&data->lock, except);

		/* Notify transmission done */
		MBOX_TEST_MSG("th_recv : notify tx done");
		mbox_tx_done(&data->handle);

		if (reply)
			mbox_rx_data(&data->handle, data->rx_data);
		count--;
	}
	MBOX_TEST_MSG("th_recv : Done");
	res = TEE_SUCCESS;
out:
	except = cpu_spin_lock_xsave(&data->lock);
	data->thread = false;
	cpu_spin_unlock_xrestore(&data->lock, except);

	return res;
}

static TEE_Result thread_test_send(struct virt_mbx_data *data,
				   const void *buff, bool wait, int count)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t except = 0;

	if (count > 1 && !wait)
		return TEE_ERROR_BAD_PARAMETERS;

	res = wait_chan_enabled(data);
	if (res)
		return res;

	except = cpu_spin_lock_xsave(&data->lock);
	if (data->thread) {
		cpu_spin_unlock_xrestore(&data->lock, except);
		return TEE_ERROR_BUSY;
	}
	data->thread = true;
	cpu_spin_unlock_xrestore(&data->lock, except);
	/* Wait till message can be queued */
	MBOX_TEST_MSG("th_send : Start");
	while (count > 0) {
		/* Wait till message can be queued */
		MBOX_TEST_MSG("th_send : wait fifo rx empty");
		res = wait_fifo_state(data, &data->rx_full, 0, "rx empty");
		if (res)
			goto out;

		if (atomic_load_int(&data->tx_full) && wait) {
			MBOX_TEST_MSG("tx channel = %s is already full",
				      data->name);
			res = TEE_ERROR_BUSY;
			goto out;
		}

		except = cpu_spin_lock_xsave(&data->lock);
		memcpy(data->rx_data, buff, sizeof(data->rx_data));
		atomic_store_int(&data->rx_full, 1);
		cpu_spin_unlock_xrestore(&data->lock, except);
		mbox_rx_data(&data->handle, data->rx_data);

		if (!wait) {
			res = TEE_SUCCESS;
			goto out;
		}
		MBOX_TEST_MSG("th_send : wait fifo tx full");
		res = wait_fifo_state(data, &data->tx_full, 1, "tx full");
		if (res)
			goto out;

		except = cpu_spin_lock_xsave(&data->lock);
		if (memcmp(data->tx_data, buff, sizeof(data->tx_data))) {
			MBOX_TEST_MSG("th_send : Receive message check : KO");
			res = TEE_ERROR_GENERIC;
		} else {
			MBOX_TEST_MSG("th_send : Receive message check : OK");
		}
		atomic_store_int(&data->tx_full, 0);
		cpu_spin_unlock_xrestore(&data->lock, except);
		/* Notify transmission done */
		mbox_tx_done(&data->handle);
		count--;
	}
	MBOX_TEST_MSG("th_send : Done");
out:
	except = cpu_spin_lock_xsave(&data->lock);
	data->thread = false;
	cpu_spin_unlock_xrestore(&data->lock, except);

	return res;
}

static TEE_Result virt_mbox_send(const struct mbox_chan *chan,
				 const void *buff, size_t len)
{
	struct virt_mbx_data *data =
		(struct virt_mbx_data *)chan->mbox_dev->desc->priv;
	uint32_t except = 0;

	/* No data transmission, only doorbell */
	if (len > VIRT_CHAN_SIZE)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!data->enabled) {
		MBOX_TEST_MSG("chan %s not enabled", data->name);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	MBOX_TEST_MSG("Send msg on channel %s", data->name);

	/* Check that the channel is free (otherwise wait) */
	MBOX_TEST_MSG("send :check tx empty");
	if (atomic_load_int(&data->tx_full)) {
		MBOX_TEST_MSG("send %s: tx full", data->name);
		return TEE_ERROR_BUSY;
	}

	except = cpu_spin_lock_xsave(&data->lock);
	memcpy(data->tx_data, buff, len);
	atomic_store_int(&data->tx_full, 1);
	cpu_spin_unlock_xrestore(&data->lock, except);
	MBOX_TEST_MSG("send: done");

	return TEE_SUCCESS;
}

static size_t virt_mbox_get_mtu(const struct mbox_chan *chan __unused)
{
	return (size_t)VIRT_CHAN_SIZE;
}

static TEE_Result virt_mbox_enable(const struct mbox_chan *chan,
				   bool enable)
{
	struct virt_mbx_data *data = (struct virt_mbx_data *)
		chan->mbox_dev->desc->priv;
	uint32_t except = 0;
	TEE_Result res = TEE_SUCCESS;

	except = cpu_spin_lock_xsave(&data->lock);
	if (data->enabled == enable)
		res = TEE_ERROR_BAD_STATE;
	data->enabled = enable;
	cpu_spin_unlock_xrestore(&data->lock, except);

	return res;
}

static TEE_Result virt_mbox_complete(struct mbox_chan *chan)
{
	struct virt_mbx_data *data = (struct virt_mbx_data *)
		chan->mbox_dev->desc->priv;
	uint32_t except = 0;
	TEE_Result res = TEE_SUCCESS;

	except = cpu_spin_lock_xsave(&data->lock);
	if (!atomic_load_int(&data->rx_full)) {
		MBOX_TEST_MSG("complete : on rx empty ");
		res = TEE_ERROR_BAD_STATE;
	}
	MBOX_TEST_MSG("complete : set rx empty ");
	atomic_store_int(&data->rx_full, 0);
	/*  clean data  */
	memset(data->rx_data, 0xff, sizeof(data->rx_data));
	cpu_spin_unlock_xrestore(&data->lock, except);

	return res;
}

static uint32_t virt_mbox_capabilities(const void *priv __unused)
{
	return MBOX_TX_NOTIF_CAP;
}

/* Capabilities of a device unable to report the end of a transmission */
static uint32_t virt_mbox_no_capabilities(const void *priv __unused)
{
	return 0;
}

static const struct mbox_ops virt_mbox_ops = {
	.send = virt_mbox_send,
	.max_data_size = virt_mbox_get_mtu,
	.channel_interrupt = virt_mbox_enable,
	.complete = virt_mbox_complete,
	.capabilities = virt_mbox_capabilities,
};

static const struct mbox_ops virt_mbox_ops_no_tx_notif = {
	.send = virt_mbox_send,
	.max_data_size = virt_mbox_get_mtu,
	.channel_interrupt = virt_mbox_enable,
	.complete = virt_mbox_complete,
	.capabilities = virt_mbox_no_capabilities,
};

static TEE_Result virt_mbox_init(struct virt_mbx_data **pdata,
				 const char *name,
				 const struct mbox_ops *ops)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	/* Local structure provided to mailbox framework for content usage */
	struct virt_mbx_data *data = NULL;
	struct mbox_dev *mdev;
	struct mbox_desc *desc;

	/*  Allocate virt_mbx_data, init value is all 0 */
	data = calloc(1, sizeof(*data));
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*  Allocate desc  */
	desc = calloc(1, sizeof(*desc));
	if (!desc) {
		free(data);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	desc->ops = ops;
	desc->priv = (void *)data;

	/* Register device to mailbox framework */
	res =  mbox_register(&mdev, desc);
	if (res) {
		free(desc);
		free(data);
	} else {
		*pdata = data;
		/*  Initialized handle in data */
		data->handle.mbox_dev = mdev;
		strlcpy(data->name, name, sizeof(data->name));
	}

	return res;
}

static TEE_Result test_recv_send(struct virt_mbx_data *data,
				 int count)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t buffer[VIRT_CHAN_SIZE + 2] = {0};
	struct mbox_chan *handle = &data->handle;

	if (!data->used) {
		/*  register handle without callback*/
		res = mbox_register_chan(NULL, NULL, NULL, handle);
		if (res != TEE_SUCCESS) {
			MBOX_TEST_MSG("Receive/send : register channel KO");
			return res;
		}
		data->used = true;
	}

	MBOX_TEST_MSG("Receive/send : mailbox blocking api test: start");
	while (count > 0) {
		res = mbox_recv(handle, true, buffer, VIRT_CHAN_SIZE);

		if (res != TEE_SUCCESS) {
			MBOX_TEST_MSG("Receive/send : receive message KO");
			return res;
		}
		MBOX_TEST_MSG("Receive/send : Receive message: OK");
		res = mbox_send(handle, true, buffer, VIRT_CHAN_SIZE);
		if (res != TEE_SUCCESS) {
			MBOX_TEST_MSG("Receive/send : failed to send message");
			return res;
		}
		MBOX_TEST_MSG("Receive/send : Send message: OK");
		count--;
	}

	return TEE_SUCCESS;
}

static TEE_Result test_send_rcv(struct virt_mbx_data *data,
				const uint8_t *info, int count)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t buffer[VIRT_CHAN_SIZE + 2] = {0};
	struct mbox_chan *handle = &data->handle;

	if (!data->used) {
		/*  register handle without callback*/
		res = mbox_register_chan(NULL, NULL, NULL, handle);
		if (res != TEE_SUCCESS) {
			MBOX_TEST_MSG("failed to register channel");
			return res;
		}
		data->used = true;
	}

	MBOX_TEST_MSG("Send/receive : mailbox blocking api test: start");
	while (count > 0) {
		res = mbox_send(handle, true, info, VIRT_CHAN_SIZE);
		if (res != TEE_SUCCESS) {
			MBOX_TEST_MSG("Send/receive : failed to send message");
			return res;
		}
		MBOX_TEST_MSG("Send/receive : Send message: OK");
		res = mbox_recv(handle, true, buffer, VIRT_CHAN_SIZE);

		if (res != TEE_SUCCESS) {
			MBOX_TEST_MSG("Send/receive : receive message KO");
			return res;
		}
		MBOX_TEST_MSG("Send/receive :Receive message: OK");
		if (memcmp(info, buffer, sizeof(buffer) - 2)) {
			MBOX_TEST_MSG("Send/receive: Receive message check KO");
			return TEE_ERROR_GENERIC;
		}
		MBOX_TEST_MSG("Send/receive :Receive message check OK");
		count--;
	}

	return TEE_SUCCESS;
}

static const uint8_t tx_data[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
	0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
static const uint8_t rx_data[] = {0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7,
	0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0};

/*
 * Software only test of the mailbox consumer callbacks.
 *
 * The virtual mailbox device drives the framework through mbox_tx_done() and
 * mbox_rx_data() the same way a real device does from its interrupt handler.
 * Only the non blocking flavour of mbox_send() and mbox_recv() is used, hence
 * this test does not depend on asynchronous notifications.
 */
#define CHAN_CB_NAME "CB" /* Channel exercising the consumer callbacks */
#define CHAN_NO_TX_NAME "NTX" /* Channel of a device without tx notification */

static struct virt_mbx_data *virt_mbox_data_cb;
static struct virt_mbx_data *virt_mbox_data_no_tx;

static void test_cb_transmit(void *cookie)
{
	struct virt_mbx_data *data = cookie;

	data->tx_cb_count++;
}

static void test_cb_receive(void *cookie)
{
	struct virt_mbx_data *data = cookie;

	data->rx_cb_count++;
}

static TEE_Result test_cb_init(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!virt_mbox_data_cb) {
		res = virt_mbox_init(&virt_mbox_data_cb, CHAN_CB_NAME,
				     &virt_mbox_ops);
		if (res)
			return res;
	}

	if (virt_mbox_data_cb->used)
		return TEE_SUCCESS;

	res = mbox_register_chan(test_cb_receive, test_cb_transmit,
				 virt_mbox_data_cb,
				 &virt_mbox_data_cb->handle);
	if (res) {
		MBOX_TEST_MSG("Callback : failed to register channel");
		return res;
	}
	virt_mbox_data_cb->used = true;

	return TEE_SUCCESS;
}

static TEE_Result test_cb_send(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct virt_mbx_data *data = NULL;
	struct mbox_chan *handle = NULL;
	unsigned int count = 0;

	res = test_cb_init();
	if (res)
		return res;

	data = virt_mbox_data_cb;
	handle = &data->handle;
	count = data->tx_cb_count;

	MBOX_TEST_MSG("Callback send : start");

	/* The device accepts the message and holds it until it is consumed */
	res = mbox_send(handle, false, tx_data, VIRT_CHAN_SIZE);
	if (res != TEE_SUCCESS) {
		MBOX_TEST_MSG("Callback send : first send failed %#" PRIx32,
			      res);
		return TEE_ERROR_GENERIC;
	}

	/* The channel is busy as long as the remote did not consume it */
	res = mbox_send(handle, false, tx_data, VIRT_CHAN_SIZE);
	if (res != TEE_ERROR_BUSY) {
		MBOX_TEST_MSG("Callback send : expected busy, got %#" PRIx32,
			      res);
		return TEE_ERROR_GENERIC;
	}

	if (data->tx_cb_count != count) {
		MBOX_TEST_MSG("Callback send : unexpected transmit callback");
		return TEE_ERROR_GENERIC;
	}

	/* Emulate the remote consuming the message */
	atomic_store_int(&data->tx_full, 0);
	mbox_tx_done(handle);

	if (data->tx_cb_count != count + 1) {
		MBOX_TEST_MSG("Callback send : transmit callback not called");
		return TEE_ERROR_GENERIC;
	}

	/* The channel is free again */
	res = mbox_send(handle, false, tx_data, VIRT_CHAN_SIZE);
	if (res != TEE_SUCCESS) {
		MBOX_TEST_MSG("Callback send : last send failed %#" PRIx32,
			      res);
		return TEE_ERROR_GENERIC;
	}

	/* Leave the channel idle for a next run */
	atomic_store_int(&data->tx_full, 0);
	mbox_tx_done(handle);

	MBOX_TEST_MSG("Callback send : done");

	return TEE_SUCCESS;
}

static TEE_Result test_cb_recv(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct virt_mbx_data *data = NULL;
	struct mbox_chan *handle = NULL;
	uint8_t buffer[VIRT_CHAN_SIZE] = {0};
	unsigned int count = 0;

	res = test_cb_init();
	if (res)
		return res;

	data = virt_mbox_data_cb;
	handle = &data->handle;
	count = data->rx_cb_count;

	MBOX_TEST_MSG("Callback receive : start");

	/* No message posted by the remote yet */
	res = mbox_recv(handle, false, buffer, sizeof(buffer));
	if (res != TEE_ERROR_NO_DATA) {
		MBOX_TEST_MSG("Callback receive : expected no data, got %#"
			      PRIx32, res);
		return TEE_ERROR_GENERIC;
	}

	if (data->rx_cb_count != count) {
		MBOX_TEST_MSG("Callback receive : unexpected receive callback");
		return TEE_ERROR_GENERIC;
	}

	/* Emulate a message posted by the remote */
	memcpy(data->rx_data, rx_data, sizeof(data->rx_data));
	atomic_store_int(&data->rx_full, 1);
	mbox_rx_data(handle, data->rx_data);

	if (data->rx_cb_count != count + 1) {
		MBOX_TEST_MSG("Callback receive : receive callback not called");
		return TEE_ERROR_GENERIC;
	}

	res = mbox_recv(handle, false, buffer, sizeof(buffer));
	if (res != TEE_SUCCESS) {
		MBOX_TEST_MSG("Callback receive : receive failed %#" PRIx32,
			      res);
		return TEE_ERROR_GENERIC;
	}

	if (memcmp(buffer, rx_data, sizeof(buffer))) {
		MBOX_TEST_MSG("Callback receive : message content check KO");
		return TEE_ERROR_GENERIC;
	}

	/* The message was consumed, the channel is empty again */
	res = mbox_recv(handle, false, buffer, sizeof(buffer));
	if (res != TEE_ERROR_NO_DATA) {
		MBOX_TEST_MSG("Callback receive : expected no data, got %#"
			      PRIx32, res);
		return TEE_ERROR_GENERIC;
	}

	MBOX_TEST_MSG("Callback receive : done");

	return TEE_SUCCESS;
}

/*
 * Tests of the invalid parameter paths of the consumer API. They only use the
 * non blocking flavour of the API and therefore do not require asynchronous
 * notifications.
 */

static TEE_Result expect_res(TEE_Result res, TEE_Result expected,
			     const char *what __unused)
{
	if (res == expected)
		return TEE_SUCCESS;

	MBOX_TEST_MSG("%s: expected %#" PRIx32 ", got %#" PRIx32,
		      what, expected, res);

	return TEE_ERROR_GENERIC;
}

/*
 * Device reporting no transmission notification capability, registered with a
 * channel free of any consumer callback.
 */
static TEE_Result test_no_tx_notif_init(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!virt_mbox_data_no_tx) {
		res = virt_mbox_init(&virt_mbox_data_no_tx, CHAN_NO_TX_NAME,
				     &virt_mbox_ops_no_tx_notif);
		if (res)
			return res;
	}

	if (virt_mbox_data_no_tx->used)
		return TEE_SUCCESS;

	res = mbox_register_chan(NULL, NULL, NULL,
				 &virt_mbox_data_no_tx->handle);
	if (res) {
		MBOX_TEST_MSG("No tx notif : failed to register channel");
		return res;
	}
	virt_mbox_data_no_tx->used = true;

	return TEE_SUCCESS;
}

static TEE_Result test_register_incorrect(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct mbox_chan chan = { };
	size_t max_size = 0;

	MBOX_TEST_MSG("Register incorrect : start");

	res = expect_res(mbox_data_max_size(NULL, &max_size),
			 TEE_ERROR_BAD_PARAMETERS,
			 "max size on a NULL handle");
	if (res)
		return res;

	res = expect_res(mbox_register_chan(NULL, NULL, NULL, NULL),
			 TEE_ERROR_BAD_PARAMETERS, "register a NULL channel");
	if (res)
		return res;

	res = expect_res(mbox_register_chan(NULL, NULL, NULL, &chan),
			 TEE_ERROR_BAD_PARAMETERS,
			 "register a channel without device");
	if (res)
		return res;

	res = test_no_tx_notif_init();
	if (res)
		return res;

	res = expect_res(mbox_data_max_size(&virt_mbox_data_no_tx->handle,
					    NULL),
			 TEE_ERROR_BAD_PARAMETERS,
			 "max size into a NULL size");
	if (res)
		return res;

	/*
	 * A transmission callback cannot be honoured by a device unable to
	 * report the end of a transmission.
	 */
	res = expect_res(mbox_register_chan(NULL, test_cb_transmit,
					    virt_mbox_data_no_tx,
					    &virt_mbox_data_no_tx->handle),
			 TEE_ERROR_NOT_SUPPORTED,
			 "register a tx callback without tx capability");
	if (res)
		return res;

	MBOX_TEST_MSG("Register incorrect : done");

	return TEE_SUCCESS;
}

static TEE_Result test_send_incorrect(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t buffer[VIRT_CHAN_SIZE + 1] = {0};
	struct mbox_chan *handle = NULL;

	MBOX_TEST_MSG("Send incorrect : start");

	res = expect_res(mbox_send(NULL, false, buffer, VIRT_CHAN_SIZE),
			 TEE_ERROR_BAD_PARAMETERS, "send on a NULL handle");
	if (res)
		return res;

	res = test_cb_init();
	if (res)
		return res;

	handle = &virt_mbox_data_cb->handle;

	/*
	 * A blocking send is refused when the consumer registered a
	 * transmission callback, and when asynchronous notifications are not
	 * available at all.
	 */
	res = expect_res(mbox_send(handle, true, buffer, VIRT_CHAN_SIZE),
			 IS_ENABLED(CFG_CORE_ASYNC_NOTIF) ?
			 TEE_ERROR_BAD_PARAMETERS : TEE_ERROR_NOT_SUPPORTED,
			 "blocking send with a tx callback");
	if (res)
		return res;

	res = expect_res(mbox_send(handle, false, buffer, VIRT_CHAN_SIZE + 1),
			 TEE_ERROR_EXCESS_DATA, "send more than the mtu");
	if (res)
		return res;

	res = test_no_tx_notif_init();
	if (res)
		return res;

	res = expect_res(mbox_send(&virt_mbox_data_no_tx->handle, true, buffer,
				   VIRT_CHAN_SIZE),
			 TEE_ERROR_NOT_SUPPORTED,
			 "blocking send without tx capability");
	if (res)
		return res;

	MBOX_TEST_MSG("Send incorrect : done");

	return TEE_SUCCESS;
}

static TEE_Result test_recv_incorrect(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t buffer[VIRT_CHAN_SIZE + 1] = {0};
	struct mbox_chan *handle = NULL;

	MBOX_TEST_MSG("Receive incorrect : start");

	res = expect_res(mbox_recv(NULL, false, buffer, VIRT_CHAN_SIZE),
			 TEE_ERROR_BAD_PARAMETERS, "receive on a NULL handle");
	if (res)
		return res;

	res = test_cb_init();
	if (res)
		return res;

	handle = &virt_mbox_data_cb->handle;

	/*
	 * A blocking receive is refused when the consumer registered a
	 * reception callback, and when asynchronous notifications are not
	 * available at all.
	 */
	res = expect_res(mbox_recv(handle, true, buffer, VIRT_CHAN_SIZE),
			 IS_ENABLED(CFG_CORE_ASYNC_NOTIF) ?
			 TEE_ERROR_BAD_PARAMETERS : TEE_ERROR_NOT_SUPPORTED,
			 "blocking receive with a rx callback");
	if (res)
		return res;

	res = expect_res(mbox_recv(handle, false, buffer, VIRT_CHAN_SIZE + 1),
			 TEE_ERROR_EXCESS_DATA, "receive more than the mtu");
	if (res)
		return res;

	res = expect_res(mbox_recv(handle, false, NULL, VIRT_CHAN_SIZE),
			 TEE_ERROR_BAD_PARAMETERS,
			 "receive into a NULL buffer");
	if (res)
		return res;

	res = expect_res(mbox_recv(handle, false, (void *)UINTPTR_MAX,
				   VIRT_CHAN_SIZE),
			 TEE_ERROR_BAD_PARAMETERS,
			 "receive into an overflowing buffer");
	if (res)
		return res;

	/* Nothing was ever posted on the channel free of callback */
	res = test_no_tx_notif_init();
	if (res)
		return res;

	res = expect_res(mbox_recv(&virt_mbox_data_no_tx->handle, false, buffer,
				   VIRT_CHAN_SIZE),
			 TEE_ERROR_NO_DATA, "receive on an empty channel");
	if (res)
		return res;

	MBOX_TEST_MSG("Receive incorrect : done");

	return TEE_SUCCESS;
}

/* Exported entrypoint for mbox tests */
TEE_Result core_mbox_tests(uint32_t ptypes,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t test = 0;
	uint32_t count = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		MBOX_TEST_MSG("bad parameters types: 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	test = params[0].value.a;

	/*
	 * These tests rely on the blocking flavour of mbox_send() and
	 * mbox_recv(), which requires asynchronous notifications.
	 */
	switch (test) {
	case PTA_MBOX_TEST_COPRO_SEND_WAIT:
	case PTA_MBOX_TEST_COPRO_WAIT_SEND:
	case PTA_MBOX_TEST_SEND_RECEIVE:
	case PTA_MBOX_TEST_RECEIVE_SEND:
		if (!IS_ENABLED(CFG_CORE_ASYNC_NOTIF)) {
			MBOX_TEST_MSG("Test %"PRIu32
				      " requires CFG_CORE_ASYNC_NOTIF", test);
			return TEE_ERROR_NOT_SUPPORTED;
		}
		break;
	default:
		break;
	}

	switch (test) {
	case PTA_MBOX_TEST_COPRO_INIT:
		if (virt_mbox_data_rx && virt_mbox_data_tx)
			return TEE_SUCCESS;
		if (!virt_mbox_data_rx) {
			res = virt_mbox_init(&virt_mbox_data_rx, CHAN_RX_NAME,
					     &virt_mbox_ops);
			if (res)
				return res;
		}
		if (!virt_mbox_data_tx) {
			res = virt_mbox_init(&virt_mbox_data_tx, CHAN_TX_NAME,
					     &virt_mbox_ops);
			if (res)
				return res;
		}
		return res;

	case PTA_MBOX_TEST_COPRO_SEND_WAIT:
		/*  Launch a thread sending and listening response  */
		count = params[0].value.b;
		if (!virt_mbox_data_rx)
			return TEE_ERROR_BAD_STATE;
		return thread_test_send(virt_mbox_data_rx, rx_data, true,
					count);
	case PTA_MBOX_TEST_COPRO_WAIT_SEND:
		/*  Launch a thread listening and response  */
		count = params[0].value.b;
		if (!virt_mbox_data_tx)
			return TEE_ERROR_BAD_STATE;
		return thread_test_recv(virt_mbox_data_tx, true,
					count);

	case PTA_MBOX_TEST_SEND_RECEIVE:
		count = params[0].value.b;
		if (!virt_mbox_data_tx)
			return TEE_ERROR_BAD_STATE;
		return test_send_rcv(virt_mbox_data_tx, tx_data, count);

	case PTA_MBOX_TEST_RECEIVE_SEND:
		count = params[0].value.b;
		if (!virt_mbox_data_rx)
			return TEE_ERROR_BAD_STATE;
		return test_recv_send(virt_mbox_data_rx, count);

	case PTA_MBOX_TEST_CALLBACK_SEND:
		return test_cb_send();

	case PTA_MBOX_TEST_CALLBACK_RECEIVE:
		return test_cb_recv();

	case PTA_MBOX_TEST_REGISTER_INCORRECT_PARAM:
		return test_register_incorrect();

	case PTA_MBOX_TEST_SEND_INCORRECT:
		return test_send_incorrect();

	case PTA_MBOX_TEST_RECEIVE_INCORRECT:
		return test_recv_incorrect();

	default:

		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}
