// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/qcom/rpm/rpm_client.h>
#include <initcall.h>
#include <inttypes.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "rpm_protocol.h"

#define RPM_REQUEST_SERVICE	QCOM_RPM_FOURCC('r', 'e', 'q', '\0')
#define RPM_MSG_KEY		QCOM_RPM_FOURCC('m', 's', 'g', '#')
#define RPM_DEFAULT_TIMEOUT_US	10000

enum rpm_inflight_status {
	RPM_INFLIGHT_PENDING = 0,
	RPM_INFLIGHT_SUCCESS,
	RPM_INFLIGHT_REJECTED, /* RPM responded with RPM_KVP_KEY_ERR */
};

#define RPM_ERR_CAPTURE_MAX	16U

struct rpm_err_capture {
	bool present;
	uint32_t wire_len;	/* exact ERR KVP value length on the wire */
	uint32_t captured_len;	/* bytes actually copied into data[] */
	bool truncated;
	uint8_t data[RPM_ERR_CAPTURE_MAX];
};

struct rpm_wire_msg {
	uint32_t service;
	uint32_t size;
	uint32_t msg_id;
	uint32_t set;
	uint32_t resource_type;
	uint32_t resource_id;
	uint32_t data_len;
	uint8_t data[];
};

struct rpm_value {
	uint8_t *data;
	size_t len;
	bool valid;
};

struct rpm_key {
	uint32_t key;
	struct rpm_value local[QCOM_RPM_NUM_SETS];
	struct rpm_value at_rpm[QCOM_RPM_NUM_SETS];
	bool dirty[QCOM_RPM_NUM_SETS];
};

struct rpm_resource {
	uint64_t identifier;
	struct rpm_key *keys;
	size_t num_keys;
	bool dirty[QCOM_RPM_NUM_SETS];
};

struct rpm_inflight {
	uint32_t msg_id;
	bool active;
	bool complete;
	enum rpm_inflight_status status;
	struct rpm_err_capture err; /* valid iff status == RPM_INFLIGHT_REJECTED */
};

struct rpm_state {
	const struct qcom_rpm_transport *transport;
	struct rpm_resource *resources;
	size_t num_resources;
	struct rpm_inflight *in_flight;
	size_t num_in_flight;
	struct mutex lock; /* Protects RPM client state */
	uint32_t next_msg_id;
	bool initialized;
};

static struct rpm_state rpm = {
	.lock = MUTEX_INITIALIZER,
	.next_msg_id = 1,
};

static bool rpm_value_equal(const struct rpm_value *a,
			    const struct rpm_value *b)
{
	if (a->valid != b->valid || a->len != b->len)
		return false;
	if (!a->valid)
		return true;

	return !memcmp(a->data, b->data, a->len);
}

static TEE_Result rpm_value_copy(struct rpm_value *dst, const void *src,
				 size_t len)
{
	uint8_t *buf = NULL;

	if (!len) {
		free(dst->data);
		dst->data = NULL;
		dst->len = 0;
		dst->valid = false;
		return TEE_SUCCESS;
	}

	buf = realloc(dst->data, len);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(buf, src, len);
	dst->data = buf;
	dst->len = len;
	dst->valid = true;

	return TEE_SUCCESS;
}

static uint64_t rpm_resource_id(uint32_t resource, uint32_t id)
{
	return ((uint64_t)resource << 32) | id;
}

static struct rpm_resource *rpm_find_resource(uint32_t resource, uint32_t id)
{
	uint64_t ident = rpm_resource_id(resource, id);
	size_t n = 0;

	for (n = 0; n < rpm.num_resources; n++)
		if (rpm.resources[n].identifier == ident)
			return rpm.resources + n;

	return NULL;
}

static TEE_Result rpm_add_resource(uint32_t resource, uint32_t id,
				   struct rpm_resource **out)
{
	struct rpm_resource *resources = NULL;
	struct rpm_resource *res = NULL;
	uint64_t ident = rpm_resource_id(resource, id);
	size_t pos = 0;

	resources = realloc(rpm.resources,
			    (rpm.num_resources + 1) * sizeof(*rpm.resources));
	if (!resources)
		return TEE_ERROR_OUT_OF_MEMORY;

	rpm.resources = resources;

	for (pos = 0; pos < rpm.num_resources; pos++)
		if (rpm.resources[pos].identifier > ident)
			break;

	if (pos < rpm.num_resources)
		memmove(rpm.resources + pos + 1, rpm.resources + pos,
			(rpm.num_resources - pos) * sizeof(*rpm.resources));

	res = rpm.resources + pos;
	memset(res, 0, sizeof(*res));
	res->identifier = ident;
	rpm.num_resources++;
	*out = res;

	return TEE_SUCCESS;
}

static TEE_Result rpm_get_resource(uint32_t resource, uint32_t id,
				   struct rpm_resource **out)
{
	struct rpm_resource *res = rpm_find_resource(resource, id);

	if (res) {
		*out = res;
		return TEE_SUCCESS;
	}

	return rpm_add_resource(resource, id, out);
}

static struct rpm_key *rpm_find_key(struct rpm_resource *res, uint32_t key)
{
	size_t n = 0;

	for (n = 0; n < res->num_keys; n++)
		if (res->keys[n].key == key)
			return res->keys + n;

	return NULL;
}

static TEE_Result rpm_add_key(struct rpm_resource *res, uint32_t key,
			      struct rpm_key **out)
{
	struct rpm_key *keys = NULL;
	struct rpm_key *slot = NULL;
	size_t pos = 0;

	keys = realloc(res->keys, (res->num_keys + 1) * sizeof(*res->keys));
	if (!keys)
		return TEE_ERROR_OUT_OF_MEMORY;

	res->keys = keys;

	for (pos = 0; pos < res->num_keys; pos++)
		if (res->keys[pos].key > key)
			break;

	if (pos < res->num_keys)
		memmove(res->keys + pos + 1, res->keys + pos,
			(res->num_keys - pos) * sizeof(*res->keys));

	slot = res->keys + pos;
	memset(slot, 0, sizeof(*slot));
	slot->key = key;
	res->num_keys++;
	*out = slot;

	return TEE_SUCCESS;
}

static TEE_Result rpm_get_key(struct rpm_resource *res, uint32_t key,
			      struct rpm_key **out)
{
	struct rpm_key *slot = rpm_find_key(res, key);

	if (slot) {
		*out = slot;
		return TEE_SUCCESS;
	}

	return rpm_add_key(res, key, out);
}

static TEE_Result rpm_update_resource(struct rpm_resource *res,
				      enum qcom_rpm_set set,
				      const struct qcom_rpm_kvp *kvps,
				      size_t num_kvps)
{
	TEE_Result ret = TEE_SUCCESS;
	bool dirty = false;
	size_t n = 0;

	if (set >= QCOM_RPM_NUM_SETS)
		return TEE_ERROR_BAD_PARAMETERS;
	if (num_kvps && !kvps)
		return TEE_ERROR_BAD_PARAMETERS;

	for (n = 0; n < num_kvps; n++) {
		struct rpm_key *slot = NULL;

		if (kvps[n].len && !kvps[n].data)
			return TEE_ERROR_BAD_PARAMETERS;

		ret = rpm_get_key(res, kvps[n].key, &slot);
		if (ret)
			return ret;

		ret = rpm_value_copy(slot->local + set, kvps[n].data,
				     kvps[n].len);
		if (ret)
			return ret;

		slot->dirty[set] =
			!rpm_value_equal(slot->local + set, slot->at_rpm + set);
		dirty = dirty || slot->dirty[set];
	}

	res->dirty[set] = false;
	for (n = 0; n < res->num_keys; n++)
		res->dirty[set] = res->dirty[set] || res->keys[n].dirty[set];

	return TEE_SUCCESS;
}

static TEE_Result rpm_kvp_encoded_len(const struct rpm_resource *res,
				      enum qcom_rpm_set set,
				      size_t *len)
{
	size_t total = 0;
	size_t n = 0;

	for (n = 0; n < res->num_keys; n++) {
		const struct rpm_key *key = res->keys + n;
		size_t value_len = key->local[set].len;
		size_t padded = 0;

		if (!key->dirty[set])
			continue;

		if (ROUNDUP_OVERFLOW(value_len, sizeof(uint32_t), &padded) ||
		    ADD_OVERFLOW(total, 2 * sizeof(uint32_t), &total) ||
		    ADD_OVERFLOW(total, padded, &total))
			return TEE_ERROR_OVERFLOW;
	}

	*len = total;
	return TEE_SUCCESS;
}

static void rpm_write32(uint8_t **p, uint32_t val)
{
	memcpy(*p, &val, sizeof(val));
	*p += sizeof(val);
}

static void rpm_commit_resource(struct rpm_resource *res, enum qcom_rpm_set set)
{
	size_t n = 0;

	for (n = 0; n < res->num_keys; n++) {
		struct rpm_key *key = res->keys + n;

		if (!key->dirty[set])
			continue;

		if (!key->local[set].valid) {
			free(key->at_rpm[set].data);
			key->at_rpm[set].data = NULL;
			key->at_rpm[set].len = 0;
			key->at_rpm[set].valid = false;
		} else {
			/*
			 * The buffer was already allocated when local was
			 * updated; failure here should not happen, so
			 * preserve dirty on OOM.
			 */
			if (rpm_value_copy(key->at_rpm + set,
					   key->local[set].data,
					   key->local[set].len))
				continue;
		}

		key->dirty[set] = false;
	}

	res->dirty[set] = false;
}

static TEE_Result rpm_encode_dirty_kvps(struct rpm_resource *res,
					enum qcom_rpm_set set,
					uint8_t **buf, size_t *len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint8_t *pos = NULL;
	size_t total = 0;
	size_t n = 0;

	ret = rpm_kvp_encoded_len(res, set, &total);
	if (ret)
		return ret;

	if (!total) {
		*buf = NULL;
		*len = 0;
		return TEE_SUCCESS;
	}

	*buf = calloc(1, total);
	if (!*buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	pos = *buf;
	for (n = 0; n < res->num_keys; n++) {
		struct rpm_key *key = res->keys + n;
		size_t padded = 0;

		if (!key->dirty[set])
			continue;

		rpm_write32(&pos, key->key);
		rpm_write32(&pos, key->local[set].len);
		if (key->local[set].len)
			memcpy(pos, key->local[set].data, key->local[set].len);
		padded = ROUNDUP(key->local[set].len, sizeof(uint32_t));
		pos += padded;
	}

	*len = total;

	return TEE_SUCCESS;
}

static uint32_t rpm_alloc_msg_id(void)
{
	uint32_t msg_id = rpm.next_msg_id++;

	if (!rpm.next_msg_id)
		rpm.next_msg_id = 1;
	if (!msg_id)
		msg_id = rpm.next_msg_id++;

	return msg_id;
}

static bool rpm_track_msg(uint32_t msg_id)
{
	struct rpm_inflight *in_flight = NULL;
	struct rpm_inflight *slot = NULL;

	in_flight = realloc(rpm.in_flight,
			    (rpm.num_in_flight + 1) * sizeof(*rpm.in_flight));
	if (!in_flight)
		return false;

	rpm.in_flight = in_flight;
	slot = rpm.in_flight + rpm.num_in_flight++;
	slot->msg_id = msg_id;
	slot->active = true;
	slot->complete = false;
	slot->status = RPM_INFLIGHT_PENDING;
	memset(&slot->err, 0, sizeof(slot->err));

	return true;
}

static bool rpm_msg_is_done(uint32_t msg_id)
{
	size_t n = 0;

	for (n = 0; n < rpm.num_in_flight; n++)
		if (rpm.in_flight[n].active &&
		    rpm.in_flight[n].msg_id == msg_id)
			return rpm.in_flight[n].complete;

	return true;
}

/* Bounded, byte-level dump of a rejected message's captured ERR value --
 * deliberately opaque, see the comment on struct rpm_err_capture.
 */
static void rpm_log_err_value(const struct rpm_inflight *slot)
{
	uint32_t n = 0;

	if (!slot->err.present) {
		EMSG("RPM: msg_id=%"PRIu32" rejected by RPM, no ERR KVP captured",
		     slot->msg_id);
		return;
	}

	EMSG("RPM: msg_id=%"PRIu32" rejected by RPM, ERR wire_len=%"PRIu32
	     " captured_len=%"PRIu32" truncated=%u", slot->msg_id,
	     slot->err.wire_len, slot->err.captured_len, slot->err.truncated);

	for (n = 0; n < slot->err.captured_len; n++)
		EMSG("RPM: ERR[%03"PRIu32"]=%#04x", n, slot->err.data[n]);
}

/* Map a completed in-flight entry's RPM-side outcome to a TEE_Result. */
static TEE_Result rpm_msg_result(uint32_t msg_id)
{
	size_t n = 0;

	for (n = 0; n < rpm.num_in_flight; n++) {
		struct rpm_inflight *slot = rpm.in_flight + n;

		if (!slot->active || slot->msg_id != msg_id)
			continue;

		if (slot->status == RPM_INFLIGHT_REJECTED) {
			rpm_log_err_value(slot);
			return TEE_ERROR_ITEM_NOT_FOUND;
		}

		return TEE_SUCCESS;
	}

	return TEE_SUCCESS;
}

static void rpm_complete_msg(uint32_t msg_id, enum rpm_inflight_status status,
			     const uint8_t *err_value, uint32_t err_len)
{
	size_t n = 0;

	for (n = 0; n < rpm.num_in_flight; n++) {
		struct rpm_inflight *slot = rpm.in_flight + n;

		if (slot->active && slot->msg_id == msg_id) {
			slot->complete = true;
			slot->status = status;

			if (status == RPM_INFLIGHT_REJECTED && err_value) {
				uint32_t copy_len = MIN(err_len,
							 RPM_ERR_CAPTURE_MAX);

				slot->err.present = true;
				slot->err.wire_len = err_len;
				slot->err.captured_len = copy_len;
				slot->err.truncated =
					err_len > RPM_ERR_CAPTURE_MAX;
				memcpy(slot->err.data, err_value, copy_len);
			}
			return;
		}
	}
}

static void rpm_retire_msg(uint32_t msg_id)
{
	size_t n = 0;

	for (n = 0; n < rpm.num_in_flight; n++) {
		if (rpm.in_flight[n].active &&
		    rpm.in_flight[n].msg_id == msg_id) {
			memmove(rpm.in_flight + n, rpm.in_flight + n + 1,
				(rpm.num_in_flight - n - 1) *
				sizeof(*rpm.in_flight));
			rpm.num_in_flight--;
			return;
		}
	}
}

static TEE_Result rpm_send_wire(enum qcom_rpm_set set, uint32_t resource,
				uint32_t id, const void *kvp_buf,
				size_t kvp_len, uint32_t *out_msg_id)
{
	struct rpm_wire_msg *msg = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t msg_id = 0;
	size_t raw_size = 0;

	if (set >= QCOM_RPM_NUM_SETS || (kvp_len && !kvp_buf))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!rpm.transport || !rpm.transport->tx)
		return TEE_ERROR_NOT_SUPPORTED;
	if (ADD_OVERFLOW(sizeof(*msg), kvp_len, &raw_size))
		return TEE_ERROR_OVERFLOW;
	if (raw_size > UINT32_MAX)
		return TEE_ERROR_OVERFLOW;

	msg = calloc(1, raw_size);
	if (!msg)
		return TEE_ERROR_OUT_OF_MEMORY;

	msg_id = rpm_alloc_msg_id();
	msg->service = RPM_REQUEST_SERVICE;
	msg->size = raw_size - 2 * sizeof(uint32_t);
	msg->msg_id = msg_id;
	msg->set = set;
	msg->resource_type = resource;
	msg->resource_id = id;
	msg->data_len = kvp_len;

	if (kvp_len)
		memcpy(msg->data, kvp_buf, kvp_len);

	if (!rpm_track_msg(msg_id)) {
		free(msg);
		return TEE_ERROR_BUSY;
	}

	ret = rpm.transport->tx(msg, raw_size);
	if (ret) {
		rpm_retire_msg(msg_id);
		free(msg);
		return ret;
	}

	if (out_msg_id)
		*out_msg_id = msg_id;

	free(msg);
	return TEE_SUCCESS;
}

TEE_Result qcom_rpm_set_transport(const struct qcom_rpm_transport *transport)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(&rpm.lock);
	rpm.transport = transport;

	if (rpm.initialized && rpm.transport && rpm.transport->open)
		ret = rpm.transport->open();

	mutex_unlock(&rpm.lock);

	return ret;
}

TEE_Result qcom_rpm_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(&rpm.lock);

	if (rpm.initialized)
		goto out;

	if (rpm.transport && rpm.transport->open) {
		ret = rpm.transport->open();
		if (ret)
			goto out;
	}

	rpm.initialized = true;

out:
	mutex_unlock(&rpm.lock);
	return ret;
}

bool qcom_rpm_is_up(void)
{
	bool ready = false;

	mutex_lock(&rpm.lock);
	ready = rpm.transport && rpm.transport->is_ready &&
		rpm.transport->is_ready();
	mutex_unlock(&rpm.lock);

	return ready;
}

TEE_Result qcom_rpm_send_kvp_buffer(enum qcom_rpm_set set, uint32_t resource,
				    uint32_t id, const void *kvp_buf,
				    size_t kvp_len, uint32_t *msg_id)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(&rpm.lock);
	ret = rpm_send_wire(set, resource, id, kvp_buf, kvp_len, msg_id);
	mutex_unlock(&rpm.lock);

	return ret;
}

TEE_Result qcom_rpm_post_request(enum qcom_rpm_set set, uint32_t resource,
				 uint32_t id, const struct qcom_rpm_kvp *kvps,
				 size_t num_kvps, uint32_t *msg_id)
{
	struct rpm_resource *res = NULL;
	uint8_t *kvp_buf = NULL;
	TEE_Result ret = TEE_SUCCESS;
	size_t kvp_len = 0;

	mutex_lock(&rpm.lock);

	ret = rpm_get_resource(resource, id, &res);
	if (ret)
		goto out;

	ret = rpm_update_resource(res, set, kvps, num_kvps);
	if (ret)
		goto out;

	if (!res->dirty[set]) {
		if (msg_id)
			*msg_id = 0;
		goto out;
	}

	if (set != QCOM_RPM_ACTIVE_SET) {
		if (msg_id)
			*msg_id = 0;
		goto out;
	}

	ret = rpm_encode_dirty_kvps(res, set, &kvp_buf, &kvp_len);
	if (ret)
		goto out;

	ret = rpm_send_wire(set, resource, id, kvp_buf, kvp_len, msg_id);
	if (!ret)
		rpm_commit_resource(res, set);

out:
	free(kvp_buf);
	mutex_unlock(&rpm.lock);
	return ret;
}

TEE_Result qcom_rpm_force_sync(enum qcom_rpm_set set, uint32_t *last_msg_id)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t n = 0;

	if (set >= QCOM_RPM_NUM_SETS)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&rpm.lock);

	if (last_msg_id)
		*last_msg_id = 0;

	for (n = 0; n < rpm.num_resources; n++) {
		struct rpm_resource *res = rpm.resources + n;
		uint8_t *kvp_buf = NULL;
		uint32_t resource = res->identifier >> 32;
		uint32_t id = res->identifier;
		size_t kvp_len = 0;
		uint32_t msg_id = 0;

		if (!res->dirty[set])
			continue;

		ret = rpm_encode_dirty_kvps(res, set, &kvp_buf, &kvp_len);
		if (ret) {
			free(kvp_buf);
			break;
		}

		ret = rpm_send_wire(set, resource, id, kvp_buf, kvp_len,
				    &msg_id);
		free(kvp_buf);
		if (ret)
			break;

		rpm_commit_resource(res, set);
		if (last_msg_id)
			*last_msg_id = msg_id;
	}

	mutex_unlock(&rpm.lock);
	return ret;
}

TEE_Result qcom_rpm_barrier(uint32_t msg_id, uint32_t timeout_us)
{
	uint64_t timeout = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!msg_id)
		return TEE_SUCCESS;
	if (!timeout_us)
		timeout_us = RPM_DEFAULT_TIMEOUT_US;

	timeout = timeout_init_us(timeout_us);
	while (true) {
		const struct qcom_rpm_transport *transport = NULL;

		mutex_lock(&rpm.lock);
		if (rpm_msg_is_done(msg_id)) {
			TEE_Result msg_res = rpm_msg_result(msg_id);

			rpm_retire_msg(msg_id);
			mutex_unlock(&rpm.lock);
			return msg_res;
		}

		transport = rpm.transport;
		mutex_unlock(&rpm.lock);

		if (transport && transport->poll)
			ret = transport->poll();
		else
			ret = TEE_ERROR_NOT_SUPPORTED;

		if (ret && ret != TEE_ERROR_NO_DATA)
			return ret;
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;

		udelay(1);
	}
}

TEE_Result qcom_rpm_rx_callback(const void *buf, size_t len)
{
	const uint8_t *pos = buf;
	const uint8_t *end = pos + len;
	uint32_t msg_id = 0;
	const uint8_t *err_value = NULL;
	uint32_t err_len = 0;
	bool have_msg_id = false;
	bool have_err = false;

	if (!buf || len % sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&rpm.lock);

	while (pos + 2 * sizeof(uint32_t) <= end) {
		uint32_t key = 0;
		uint32_t kvp_len = 0;
		size_t padded = 0;

		memcpy(&key, pos, sizeof(key));
		pos += sizeof(key);
		memcpy(&kvp_len, pos, sizeof(kvp_len));
		pos += sizeof(kvp_len);

		if (ROUNDUP_OVERFLOW(kvp_len, sizeof(uint32_t), &padded) ||
		    pos + padded > end) {
			mutex_unlock(&rpm.lock);
			return TEE_ERROR_BAD_FORMAT;
		}

		if (key == RPM_MSG_KEY && kvp_len == sizeof(uint32_t)) {
			memcpy(&msg_id, pos, sizeof(msg_id));
			have_msg_id = true;
		} else if (key == RPM_KVP_KEY_ERR && !have_err) {
			err_value = pos;
			err_len = kvp_len;
			have_err = true;
		}

		pos += padded;
	}

	if (have_msg_id)
		rpm_complete_msg(msg_id,
				  have_err ? RPM_INFLIGHT_REJECTED :
					     RPM_INFLIGHT_SUCCESS,
				  have_err ? err_value : NULL,
				  have_err ? err_len : 0);

	mutex_unlock(&rpm.lock);
	return TEE_SUCCESS;
}

void ubsp_rpm_send(uint32_t resource_type, uint32_t id, uint32_t set,
		   uint8_t *kvps, uint32_t len)
{
	uint32_t msg_id = 0;

	if (qcom_rpm_send_kvp_buffer(set, resource_type, id, kvps, len,
				     &msg_id))
		return;

	(void)qcom_rpm_barrier(msg_id, RPM_DEFAULT_TIMEOUT_US);
}

static TEE_Result qcom_rpm_driver_init(void)
{
	TEE_Result ret = qcom_rpm_init();

	if (ret == TEE_ERROR_NOT_SUPPORTED)
		return TEE_SUCCESS;

	return ret;
}
early_init(qcom_rpm_driver_init);
