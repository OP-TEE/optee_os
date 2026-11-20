// SPDX-License-Identifier: BSD-2-Clause
#include <assert.h>
#include <atomic.h>
#include <drivers/virtio_be.h>
#include <kernel/mutex.h>
#include <malloc.h>
#include <string.h>

#include "virtio_be_private.h"

static TAILQ_HEAD(, virtio_be_dev_type) types = TAILQ_HEAD_INITIALIZER(types);
static struct mutex types_lock = MUTEX_INITIALIZER;

static struct virtio_be_dev_type *find_type_by_name(const char *name)
{
	struct virtio_be_dev_type *type = NULL;

	TAILQ_FOREACH(type, &types, link)
		if (!strcmp(type->name, name))
			return type;

	return NULL;
}

TEE_Result virtio_be_register_type(struct virtio_be_dev_type *type)
{
	size_t ds = 0;
	size_t as = 0;
	size_t us = 0;

	if (!type->name || !type->device || !type->ops)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!type->queue_count || type->queue_count > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (type->config_size > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!virtio_features_are_device_specific(&type->features))
		return TEE_ERROR_BAD_PARAMETERS;
	/* Validate queue size against split-ring requirements. */
	if (vring_split_sizes(type->max_queue_size, &ds, &as, &us))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&types_lock);
	if (find_type_by_name(type->name)) {
		mutex_unlock(&types_lock);

		return TEE_ERROR_ACCESS_CONFLICT;
	}

	type->users = 0;
	TAILQ_INSERT_TAIL(&types, type, link);
	mutex_unlock(&types_lock);

	return TEE_SUCCESS;
}

TEE_Result virtio_be_unregister_type(struct virtio_be_dev_type *type)
{
	struct virtio_be_dev_type *registered = NULL;
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	mutex_lock(&types_lock);
	TAILQ_FOREACH(registered, &types, link) {
		if (registered != type)
			continue;

		if (registered->users) {
			res = TEE_ERROR_BUSY;
			break;
		}

		TAILQ_REMOVE(&types, registered, link);

		res = TEE_SUCCESS;
		break;
	}
	mutex_unlock(&types_lock);

	return res;
}

static struct virtio_be_dev_type *acquire_type_by_name(const char *name)
{
	struct virtio_be_dev_type *type = NULL;

	mutex_lock(&types_lock);
	type = find_type_by_name(name);
	if (type)
		type->users++;
	mutex_unlock(&types_lock);

	return type;
}

static void release_type(struct virtio_be_dev_type *type)
{
	mutex_lock(&types_lock);
	type->users--;
	mutex_unlock(&types_lock);
}

/* Check whether new work is allowed; caller holds the queue mutex. */
bool virtqueue_be_running(struct virtqueue_be *vq)
{
	return vq->running &&
	       !(atomic_load_u32(&vq->vbe_dev->status) &
		 (VIRTIO_STATUS_FAILED | VIRTIO_STATUS_DEVICE_NEEDS_RESET));
}

/* Notify when a reset fault first becomes visible on an activated device. */
static void set_needs_reset(struct virtio_be_dev *vbe_dev, uint32_t bits)
{
	const uint32_t fault = VIRTIO_STATUS_DRIVER_OK |
			       VIRTIO_STATUS_DEVICE_NEEDS_RESET;
	uint32_t old = 0;

	bits |= VIRTIO_STATUS_DEVICE_NEEDS_RESET;
	old = __atomic_fetch_or(&vbe_dev->status, bits, __ATOMIC_RELAXED);

	if (((old | bits) & fault) == fault && (old & fault) != fault)
		vbe_dev->ops->notify_config(vbe_dev);
}

/* Atomically set DEVICE_NEEDS_RESET; does not acquire the device mutex. */
void virtio_be_dev_needs_reset(struct virtio_be_dev *vbe_dev)
{
	set_needs_reset(vbe_dev, 0);
}

TEE_Result virtio_be_dev_init(struct virtio_be_dev *vbe_dev, const char *name,
			      const struct virtio_be_transport_ops *ops)
{
	struct virtio_be_dev_type *type = NULL;
	struct virtio_features supported = { };
	uint16_t qid = 0;
	TEE_Result res = TEE_SUCCESS;

	*vbe_dev = (struct virtio_be_dev){ };

	virtio_feature_set(&supported, VIRTIO_F_ACCESS_PLATFORM);
	/* Reject transport requirements unsupported by the backend core. */
	if (!virtio_features_include(&supported, &ops->required_features))
		return TEE_ERROR_NOT_SUPPORTED;

	type = acquire_type_by_name(name);
	if (!type)
		return TEE_ERROR_ITEM_NOT_FOUND;

	vbe_dev->queues = calloc(type->queue_count, sizeof(*vbe_dev->queues));
	if (!vbe_dev->queues) {
		release_type(type);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	vbe_dev->type = type;
	vbe_dev->ops = ops;
	mutex_init(&vbe_dev->mutex);
	/* Copy device-specific features offered by the class. */
	vbe_dev->offered = type->features;
	/* Require modern Virtio operation. */
	virtio_feature_set(&vbe_dev->offered, VIRTIO_F_VERSION_1);
	/* Add common features required by the transport. */
	virtio_features_or(&vbe_dev->offered, &ops->required_features);

	virtio_be_for_each_queue(vbe_dev, qid) {
		virtqueue_be_init(&vbe_dev->queues[qid], vbe_dev, qid);
	}

	if (type->ops->create)
		res = type->ops->create(vbe_dev);
	if (!res)
		return TEE_SUCCESS;

	virtio_be_for_each_queue(vbe_dev, qid)
		virtqueue_be_deinit(&vbe_dev->queues[qid]);

	mutex_destroy(&vbe_dev->mutex);
	free(vbe_dev->queues);
	release_type(type);

	return res;
}

/* Set queue states under their mutexes; caller holds the device mutex. */
static void set_queues_running(struct virtio_be_dev *vbe_dev, bool running)
{
	uint16_t qid = 0;

	virtio_be_for_each_queue(vbe_dev, qid) {
		struct virtqueue_be *vq = &vbe_dev->queues[qid];

		mutex_lock(&vq->mutex);
		vq->running = running && vq->size != 0;
		mutex_unlock(&vq->mutex);
	}
}

TEE_Result virtio_be_dev_ready(struct virtio_be_dev *vbe_dev)
{
	const uint8_t setup = VIRTIO_STATUS_ACKNOWLEDGE |
			      VIRTIO_STATUS_DRIVER |
			      VIRTIO_STATUS_FEATURES_OK;

	if (virtio_be_dev_get_status(vbe_dev) != setup)
		return TEE_ERROR_BAD_STATE;

	__atomic_fetch_or(&vbe_dev->status, VIRTIO_STATUS_DRIVER_OK,
			  __ATOMIC_RELAXED);
	set_queues_running(vbe_dev, true);

	return TEE_SUCCESS;
}

/* Queue a configuration hint without modifying class-owned state. */
void virtio_be_dev_notify_config(struct virtio_be_dev *vbe_dev)
{
	if (virtio_be_dev_get_status(vbe_dev) & VIRTIO_STATUS_DRIVER_OK)
		vbe_dev->ops->notify_config(vbe_dev);
}

static void reset_device(struct virtio_be_dev *vbe_dev)
{
	uint16_t qid = 0;

	set_queues_running(vbe_dev, false);
	if (vbe_dev->started && vbe_dev->type->ops->stop)
		vbe_dev->type->ops->stop(vbe_dev);

	/* Queues are drained; the device mutex excludes restart and rebind. */
	virtio_be_for_each_queue(vbe_dev, qid)
		virtqueue_be_unbind(&vbe_dev->queues[qid]);

	vbe_dev->started = false;
	/* Clear old selections before the next word-by-word negotiation. */
	virtio_features_reset(&vbe_dev->candidate);
	atomic_store_u32(&vbe_dev->status, 0);
}

static bool valid_negotiated_features(struct virtio_be_dev *vbe_dev)
{
	struct virtio_features required = vbe_dev->ops->required_features;

	virtio_feature_set(&required, VIRTIO_F_VERSION_1);
	/* Require all unsupported mandatory bits and unoffered bits. */
	return virtio_features_include(&vbe_dev->offered,
				       &vbe_dev->candidate) &&
	       virtio_features_include(&vbe_dev->candidate, &required);
}

TEE_Result virtio_be_dev_set_status(struct virtio_be_dev *vbe_dev,
				    uint8_t status)
{
	const struct virtio_be_ops *ops = NULL;
	/* Status bits the frontend is allowed to set. */
	uint8_t allowed = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
			  VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK |
			  VIRTIO_STATUS_FAILED;
	TEE_Result res = TEE_SUCCESS;
	uint8_t old = 0;

	mutex_lock(&vbe_dev->mutex);
	ops = vbe_dev->type->ops;
	if (!status) {
		reset_device(vbe_dev);
		goto out;
	}

	old = virtio_be_dev_get_status(vbe_dev);
	/* The frontend may echo NEEDS_RESET but must not set it itself. */
	if ((status & VIRTIO_STATUS_DEVICE_NEEDS_RESET) &&
	    !(old & VIRTIO_STATUS_DEVICE_NEEDS_RESET)) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	status &= ~VIRTIO_STATUS_DEVICE_NEEDS_RESET;
	/* Unknown bits, updates after FAILED, and cleared status bits. */
	if ((status & ~allowed) || (old & VIRTIO_STATUS_FAILED) ||
	    ((status & (old & allowed)) != (old & allowed))) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (status & VIRTIO_STATUS_FAILED) {
		__atomic_fetch_or(&vbe_dev->status, VIRTIO_STATUS_FAILED,
				  __ATOMIC_RELAXED);
		set_queues_running(vbe_dev, false);
		goto out;
	}

	/* Require reset after a device fault. */
	if (old & VIRTIO_STATUS_DEVICE_NEEDS_RESET) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Enforce dependencies between initialization status bits. */
	if (((status & VIRTIO_STATUS_DRIVER) &&
	     !(status & VIRTIO_STATUS_ACKNOWLEDGE)) ||
	    ((status & VIRTIO_STATUS_FEATURES_OK) &&
	     !(status & VIRTIO_STATUS_DRIVER)) ||
	    ((status & VIRTIO_STATUS_DRIVER_OK) &&
	     !(status & VIRTIO_STATUS_FEATURES_OK))) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (status == old)
		goto out;

	if ((status & VIRTIO_STATUS_FEATURES_OK) &&
	    !(old & VIRTIO_STATUS_FEATURES_OK)) {
		if (!valid_negotiated_features(vbe_dev) ||
		    (ops->validate_features &&
		     ops->validate_features(vbe_dev, &vbe_dev->candidate))) {
			status &= ~VIRTIO_STATUS_FEATURES_OK;
		} else {
			vbe_dev->accepted = vbe_dev->candidate;
		}

		if (!(status & VIRTIO_STATUS_FEATURES_OK))
			status &= ~VIRTIO_STATUS_DRIVER_OK;
	}

	if ((status & VIRTIO_STATUS_DRIVER_OK) &&
	    !(old & VIRTIO_STATUS_DRIVER_OK)) {
		/* Publish setup status before class-controlled activation. */
		atomic_store_u32(&vbe_dev->status,
				 status & ~VIRTIO_STATUS_DRIVER_OK);
		if (ops->start)
			res = ops->start(vbe_dev);
		if (!res) {
			vbe_dev->started = true;
			/* Activate classes that did not enable their queues. */
			if (!(virtio_be_dev_get_status(vbe_dev) &
			      VIRTIO_STATUS_DRIVER_OK))
				res = virtio_be_dev_ready(vbe_dev);
		}

		if (res) {
			/* Record the driver's request and require reset. */
			set_needs_reset(vbe_dev, VIRTIO_STATUS_DRIVER_OK);
			set_queues_running(vbe_dev, false);
		}
		goto out;
	}

	atomic_store_u32(&vbe_dev->status, status);

out:
	mutex_unlock(&vbe_dev->mutex);

	return res;
}

uint8_t virtio_be_dev_get_status(struct virtio_be_dev *vbe_dev)
{
	return atomic_load_u32(&vbe_dev->status);
}

TEE_Result virtio_be_dev_get_features(struct virtio_be_dev *vbe_dev,
				      uint32_t block, uint32_t *features)
{
	if (block >= VIRTIO_FEATURE_WORDS)
		return TEE_ERROR_BAD_PARAMETERS;

	*features = vbe_dev->offered.words[block];

	return TEE_SUCCESS;
}

TEE_Result virtio_be_dev_set_features(struct virtio_be_dev *vbe_dev,
				      uint32_t block, uint32_t features)
{
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&vbe_dev->mutex);
	if (block >= VIRTIO_FEATURE_WORDS) {
		res = TEE_ERROR_BAD_PARAMETERS;
	/* Allow feature writes only during negotiation, before FEATURES_OK. */
	} else if (virtio_be_dev_get_status(vbe_dev) !=
		   (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER)) {
		res = TEE_ERROR_BAD_STATE;
	} else {
		vbe_dev->candidate.words[block] = features;
	}
	mutex_unlock(&vbe_dev->mutex);

	return res;
}

bool virtio_be_dev_has_feature(struct virtio_be_dev *vbe_dev, unsigned int bit)
{
	return virtio_feature_test(&vbe_dev->accepted, bit);
}

void *virtio_be_dev_get_data(struct virtio_be_dev *vbe_dev)
{
	return vbe_dev->data;
}

void virtio_be_dev_set_data(struct virtio_be_dev *vbe_dev, void *data)
{
	vbe_dev->data = data;
}

/* Access @size bytes of @vbe_dev configuration at @offset. */
static TEE_Result access_device_config(struct virtio_be_dev *vbe_dev,
				       uint32_t offset, void *buffer,
				       size_t size, uint32_t *generation,
				       bool write)
{
	const struct virtio_be_dev_type *type = NULL;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&vbe_dev->mutex);
	type = vbe_dev->type;
	if (offset > type->config_size || size > type->config_size - offset) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if (virtio_be_dev_get_status(vbe_dev) &
		   VIRTIO_STATUS_DEVICE_NEEDS_RESET) {
		res = TEE_ERROR_BAD_STATE;
	} else if (!size) {
		/* Query class generation without changing configuration. */
		if (type->ops->read_config)
			res = type->ops->read_config(vbe_dev, offset, NULL, 0,
						     generation);
		else
			*generation = 0;
	} else if (write && type->ops->write_config) {
		res = type->ops->write_config(vbe_dev, offset, buffer, size,
					     generation);
	} else if (!write && type->ops->read_config) {
		res = type->ops->read_config(vbe_dev, offset, buffer, size,
					    generation);
	} else {
		res = TEE_ERROR_NOT_SUPPORTED;
	}

	mutex_unlock(&vbe_dev->mutex);

	return res;
}

TEE_Result virtio_be_dev_read_config(struct virtio_be_dev *vbe_dev,
				     uint32_t offset, void *buffer,
				     size_t size, uint32_t *generation)
{
	return access_device_config(vbe_dev, offset, buffer, size, generation,
				    false);
}

TEE_Result virtio_be_dev_write_config(struct virtio_be_dev *vbe_dev,
				      uint32_t offset, const void *buffer,
				      size_t size, uint32_t *generation)
{
	return access_device_config(vbe_dev, offset, (void *)buffer, size,
				    generation, true);
}

TEE_Result
virtio_be_dev_set_queue(struct virtio_be_dev *vbe_dev, uint16_t qid,
			const struct virtio_queue_config *qinfo,
			TEE_Result (*notify)(struct virtqueue_be *vq))
{
	struct virtqueue_be *vq = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (qid >= vbe_dev->type->queue_count)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&vbe_dev->mutex);
	vq = &vbe_dev->queues[qid];
	/* Bind only after feature negotiation and before device startup. */
	if (virtio_be_dev_get_status(vbe_dev) !=
	    (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
	     VIRTIO_STATUS_FEATURES_OK)) {
		res = TEE_ERROR_BAD_STATE;
	} else {
		res = virtqueue_be_bind(vq, qinfo);
		if (!res)
			vq->notify = notify;
	}
	mutex_unlock(&vbe_dev->mutex);

	return res;
}

TEE_Result virtio_be_dev_get_queue(struct virtio_be_dev *vbe_dev, uint16_t qid,
				   struct virtio_queue_config *qinfo,
				   size_t *max_queue_size)
{
	struct virtqueue_be *vq = NULL;

	if (qid >= vbe_dev->type->queue_count)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&vbe_dev->mutex);
	vq = &vbe_dev->queues[qid];
	/* Queue size and ring addresses change only under the device mutex. */
	*max_queue_size = vbe_dev->type->max_queue_size;
	*qinfo = (struct virtio_queue_config){ };
	if (vq->size) {
		*qinfo = (struct virtio_queue_config){
			.size = vq->size,
			.desc = vq->split_ring.regions.desc.address,
			.avail = vq->split_ring.regions.avail.address,
			.used = vq->split_ring.regions.used.address,
		};
	}
	mutex_unlock(&vbe_dev->mutex);

	return TEE_SUCCESS;
}

/* Deliver a queue hint while excluding class startup and shutdown. */
TEE_Result virtio_be_dev_queue_kicked(struct virtio_be_dev *vbe_dev,
				      uint16_t qid)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t status = 0;

	if (qid >= vbe_dev->type->queue_count)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&vbe_dev->mutex);
	status = virtio_be_dev_get_status(vbe_dev);

	/* Deliver kicks only for a started device and a configured queue. */
	if (!vbe_dev->started || !vbe_dev->queues[qid].size ||
	    !(status & VIRTIO_STATUS_DRIVER_OK) ||
	    (status & (VIRTIO_STATUS_FAILED |
		       VIRTIO_STATUS_DEVICE_NEEDS_RESET))) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (vbe_dev->type->ops->queue_kicked)
		vbe_dev->type->ops->queue_kicked(vbe_dev, qid);

out:
	mutex_unlock(&vbe_dev->mutex);

	return res;
}

TEE_Result virtio_be_dev_deinit(struct virtio_be_dev *vbe_dev)
{
	uint16_t qid = 0;

	mutex_lock(&vbe_dev->mutex);
	reset_device(vbe_dev);
	/* Release class state created during initialization. */
	if (vbe_dev->type->ops->destroy)
		vbe_dev->type->ops->destroy(vbe_dev);

	virtio_be_for_each_queue(vbe_dev, qid)
		virtqueue_be_deinit(&vbe_dev->queues[qid]);
	release_type(vbe_dev->type);
	mutex_unlock(&vbe_dev->mutex);

	mutex_destroy(&vbe_dev->mutex);
	free(vbe_dev->queues);
	*vbe_dev = (struct virtio_be_dev){ };

	return TEE_SUCCESS;
}
