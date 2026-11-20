// SPDX-License-Identifier: BSD-2-Clause
#include <assert.h>
#include <drivers/virtio.h>
#include <kernel/mutex.h>
#include <sys/queue.h>

#include "virtio_private.h"

static TAILQ_HEAD(, virtio_driver) drivers = TAILQ_HEAD_INITIALIZER(drivers);
static struct mutex drivers_lock = MUTEX_INITIALIZER;

TEE_Result virtio_register_driver(struct virtio_driver *driver)
{
	struct virtio_driver *registered = NULL;
	size_t n = 0;

	if (!driver->ops->probe || !driver->ops->remove ||
	    !virtio_features_are_device_specific(&driver->required_features) ||
	    !virtio_features_are_device_specific(&driver->optional_features))
		return TEE_ERROR_BAD_PARAMETERS;

	for (n = 0; n < driver->num_ids; n++)
		if (!driver->ids[n].device)
			return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&drivers_lock);
	TAILQ_FOREACH(registered, &drivers, link) {
		if (registered == driver) {
			mutex_unlock(&drivers_lock);
			return TEE_ERROR_ACCESS_CONFLICT;
		}
	}
	driver->users = 0;
	TAILQ_INSERT_TAIL(&drivers, driver, link);
	mutex_unlock(&drivers_lock);

	return TEE_SUCCESS;
}

TEE_Result virtio_unregister_driver(struct virtio_driver *driver)
{
	struct virtio_driver *registered = NULL;
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	mutex_lock(&drivers_lock);
	TAILQ_FOREACH(registered, &drivers, link) {
		if (registered != driver)
			continue;

		if (registered->users) {
			res = TEE_ERROR_BUSY;
			break;
		}

		TAILQ_REMOVE(&drivers, registered, link);

		res = TEE_SUCCESS;
		break;
	}
	mutex_unlock(&drivers_lock);

	return res;
}

static struct virtio_driver *acquire_driver(struct virtio_device *vdev)
{
	struct virtio_driver *driver = NULL;
	size_t n = 0;

	mutex_lock(&drivers_lock);
	TAILQ_FOREACH(driver, &drivers, link) {
		for (n = 0; n < driver->num_ids; n++) {
			if (driver->ids[n].device != vdev->info.id.device ||
			    (driver->ids[n].vendor != VIRTIO_VENDOR_ANY &&
			     driver->ids[n].vendor != vdev->info.id.vendor))
				continue;
			driver->users++;
			mutex_unlock(&drivers_lock);

			return driver;
		}
	}
	mutex_unlock(&drivers_lock);

	return NULL;
}

static void release_driver(struct virtio_device *vdev)
{
	mutex_lock(&drivers_lock);
	vdev->driver->users--;
	vdev->driver = NULL;
	mutex_unlock(&drivers_lock);
}

const struct virtio_device_info *
virtio_device_get_info(struct virtio_device *vdev)
{
	return &vdev->info;
}

bool virtio_device_is_ready(struct virtio_device *vdev)
{
	uint8_t status = 0;

	if (vdev->ops->get_status(vdev, &status))
		return false;

	return (status & VIRTIO_STATUS_DRIVER_OK) &&
	       !(status & (VIRTIO_STATUS_FAILED |
			   VIRTIO_STATUS_DEVICE_NEEDS_RESET));
}

bool virtio_has_feature(struct virtio_device *vdev, unsigned int bit)
{
	return bit < VIRTIO_FEATURE_BITS &&
	       virtio_feature_test(&vdev->features, bit);
}

void virtio_set_drvdata(struct virtio_device *vdev, void *data)
{
	vdev->drvdata = data;
}

void *virtio_get_drvdata(struct virtio_device *vdev)
{
	return vdev->drvdata;
}

static TEE_Result validate_config_access(struct virtio_device *vdev,
					 uint32_t offset, size_t size)
{
	if (offset > vdev->info.config_size ||
	    size > vdev->info.config_size - offset)
		return TEE_ERROR_BAD_PARAMETERS;
	/* Configuration access is allowed only after successful negotiation. */
	if (!virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

/* Read @size bytes of @vdev config at @offset into @buffer. */
TEE_Result virtio_config_read(struct virtio_device *vdev, uint32_t offset,
			      void *buffer, size_t size)
{
	TEE_Result res = validate_config_access(vdev, offset, size);

	if (res || !size)
		return res;

	if (!vdev->ops->read_config)
		return TEE_ERROR_NOT_SUPPORTED;

	for (;;) {
		uint32_t before = 0;
		uint32_t after = 0;
		/* Record the configuration generation before reading. */
		res = vdev->ops->get_config_generation(vdev, &before);
		if (res)
			return res;
		res = vdev->ops->read_config(vdev, offset, buffer, size);
		if (res)
			return res;
		/* Check whether configuration changed during the read. */
		res = vdev->ops->get_config_generation(vdev, &after);
		if (res)
			return res;

		if (before == after)
			return TEE_SUCCESS;
	}
}

/* Write @size bytes from @buffer to @vdev config at @offset. */
TEE_Result virtio_config_write(struct virtio_device *vdev, uint32_t offset,
			       const void *buffer, size_t size)
{
	TEE_Result res = validate_config_access(vdev, offset, size);

	if (res || !size)
		return res;

	if (!vdev->ops->write_config)
		return TEE_ERROR_NOT_SUPPORTED;
	return vdev->ops->write_config(vdev, offset, buffer, size);
}

TEE_Result virtio_setup_queues(struct virtio_device *vdev, size_t count,
			      const struct virtqueue_info *info,
			      struct virtqueue **queues)
{
	uint16_t qid = 0;

	if (!count || count > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!TAILQ_EMPTY(&vdev->queues))
		return TEE_ERROR_BAD_STATE;

	for (qid = 0; qid < count; qid++)
		if (!info[qid].name)
			return TEE_ERROR_BAD_PARAMETERS;

	return vdev->ops->setup_queues(vdev, info, count, queues);
}

void virtio_release_queues(struct virtio_device *vdev)
{
	if (TAILQ_EMPTY(&vdev->queues))
		return;

	vdev->ops->release_queues(vdev);
}

TEE_Result virtio_device_init(struct virtio_device *vdev,
			      const struct virtio_transport_ops *ops,
			      const struct virtio_map_ops *map_ops)
{
	struct virtio_features supported = { };
	TEE_Result res = TEE_SUCCESS;

	*vdev = (struct virtio_device){ };
	TAILQ_INIT(&vdev->queues);
	if (!map_ops || !map_ops->map || !map_ops->release)
		return TEE_ERROR_BAD_PARAMETERS;

	virtio_feature_set(&supported, VIRTIO_F_ACCESS_PLATFORM);
	/* Reject required transport features unsupported by the core. */
	if (!virtio_features_include(&supported, &ops->required_features))
		return TEE_ERROR_NOT_SUPPORTED;

	vdev->ops = ops;
	vdev->map_ops = map_ops;
	res = ops->get_info(vdev, &vdev->info);
	if (!res && (!vdev->info.id.device ||
		     vdev->info.config_size > UINT32_MAX))
		res = TEE_ERROR_BAD_PARAMETERS;

	return res;
}

static TEE_Result reset_device(struct virtio_device *vdev)
{
	uint8_t status = 0;
	TEE_Result res = TEE_SUCCESS;

	res = vdev->ops->reset(vdev);
	if (res)
		return res;
	/* Confirm that reset cleared the device status. */
	res = vdev->ops->get_status(vdev, &status);
	if (res)
		return res;
	if (status)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

/* Add @bits to @vdev status and verify that the device accepted them. */
static TEE_Result set_status_bits(struct virtio_device *vdev, uint8_t bits)
{
	uint8_t before = 0;
	uint8_t after = 0;
	TEE_Result res = TEE_SUCCESS;

	res = vdev->ops->get_status(vdev, &before);
	if (res)
		return res;
	/* Require reset before advancing a failed device's status. */
	if (before & (VIRTIO_STATUS_DEVICE_NEEDS_RESET | VIRTIO_STATUS_FAILED))
		return TEE_ERROR_BAD_STATE;

	res = vdev->ops->set_status(vdev, before | bits);
	if (res)
		return res;

	res = vdev->ops->get_status(vdev, &after);
	if (res)
		return res;
	if (after & (VIRTIO_STATUS_DEVICE_NEEDS_RESET | VIRTIO_STATUS_FAILED))
		return TEE_ERROR_BAD_STATE;
	if ((after & (before | bits)) != (before | bits)) {
		/* Clearing FEATURES_OK rejects the negotiated features. */
		if (bits == VIRTIO_STATUS_FEATURES_OK)
			return TEE_ERROR_NOT_SUPPORTED;

		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

/* Enable @vdev after probe setup and before starting queue users. */
TEE_Result virtio_device_ready(struct virtio_device *vdev)
{
	const uint8_t setup = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
			      VIRTIO_STATUS_FEATURES_OK;
	uint8_t status = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!vdev->driver || !vdev->probe_entered)
		return TEE_ERROR_BAD_STATE;

	res = vdev->ops->get_status(vdev, &status);
	if (res)
		return res;
	if (status != setup)
		return TEE_ERROR_BAD_STATE;

	return set_status_bits(vdev, VIRTIO_STATUS_DRIVER_OK);
}

static TEE_Result negotiate_device_features(struct virtio_device *vdev)
{
	const struct virtio_driver *driver = vdev->driver;
	struct virtio_features required = driver->required_features;
	struct virtio_features selected = { };
	struct virtio_features offered = { };
	struct virtio_features allowed = { };
	TEE_Result res = TEE_SUCCESS;
	/* Limit negotiation to feature blocks supported by this core. */
	size_t blocks = MIN(vdev->info.feature_blocks, VIRTIO_FEATURE_WORDS);
	size_t n = 0;

	for (n = 0; n < blocks; n++) {
		res = vdev->ops->get_features(vdev, n, &offered.words[n]);
		if (res)
			return res;
	}

	virtio_features_or(&required, &vdev->ops->required_features);
	virtio_feature_set(&required, VIRTIO_F_VERSION_1);
	if (!virtio_features_include(&offered, &required))
		return TEE_ERROR_NOT_SUPPORTED;

	selected = required;
	virtio_features_or(&selected, &driver->optional_features);
	virtio_features_and(&selected, &offered);
	/* selected = required features | offered optional features. */
	allowed = selected;

	if (driver->ops->negotiate_features) {
		/* Check class dependencies and drop optional features. */
		res = driver->ops->negotiate_features(vdev, &selected);
		if (res)
			return res;
		if (!virtio_features_include(&selected, &required) ||
		    !virtio_features_include(&allowed, &selected))
			return TEE_ERROR_BAD_PARAMETERS;
	}

	for (n = 0; n < blocks; n++) {
		res = vdev->ops->set_features(vdev, n, selected.words[n]);
		if (res)
			return res;
	}

	res = set_status_bits(vdev, VIRTIO_STATUS_FEATURES_OK);
	if (!res)
		vdev->features = selected;

	return res;
}

/* Confirm peer reset after the class has stopped queue and config users. */
TEE_Result virtio_reset_device(struct virtio_device *vdev)
{
	struct virtqueue *vq = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = reset_device(vdev);
	if (res)
		return res;

	TAILQ_FOREACH(vq, &vdev->queues, link)
		vq->stopped = true;

	return TEE_SUCCESS;
}

TEE_Result virtio_device_deinit(struct virtio_device *vdev)
{
	TEE_Result res = TEE_SUCCESS;

	if (vdev->driver && vdev->probe_entered)
		res = vdev->driver->ops->remove(vdev);
	else
		res = virtio_reset_device(vdev);
	if (res)
		return res;

	if (vdev->driver)
		release_driver(vdev);

	vdev->probe_entered = false;
	vdev->drvdata = NULL;
	virtio_features_reset(&vdev->features);

	return TEE_SUCCESS;
}

TEE_Result virtio_device_start(struct virtio_device *vdev)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t status = 0;

	if (vdev->driver)
		return TEE_ERROR_BAD_STATE;

	vdev->driver = acquire_driver(vdev);
	if (!vdev->driver)
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = reset_device(vdev);
	if (res)
		goto fail;
	res = set_status_bits(vdev, VIRTIO_STATUS_ACKNOWLEDGE);
	if (res)
		goto fail;
	res = set_status_bits(vdev, VIRTIO_STATUS_DRIVER);
	if (res)
		goto fail;
	res = negotiate_device_features(vdev);
	if (res)
		goto fail;
	vdev->probe_entered = true;
	res = vdev->driver->ops->probe(vdev);
	if (res)
		goto fail;
	res = vdev->ops->get_status(vdev, &status);
	if (res)
		goto fail;
	if (status & (VIRTIO_STATUS_FAILED |
		      VIRTIO_STATUS_DEVICE_NEEDS_RESET)) {
		res = TEE_ERROR_BAD_STATE;
		goto fail;
	}
	/* Complete startup if the class did not enable the device in probe. */
	if (!(status & VIRTIO_STATUS_DRIVER_OK)) {
		res = virtio_device_ready(vdev);
		if (res)
			goto fail;
	}

	return TEE_SUCCESS;

fail:
	if (!vdev->ops->get_status(vdev, &status))
		vdev->ops->set_status(vdev, status | VIRTIO_STATUS_FAILED);
	/* Preserve the startup error; failed cleanup retains the driver pin. */
	virtio_device_deinit(vdev);

	return res;
}

/* Dispatch a configuration hint after successful device startup. */
void virtio_config_changed(struct virtio_device *vdev)
{
	if (vdev->driver->ops->config_changed)
		vdev->driver->ops->config_changed(vdev);
}

/* Dispatch a received queue hint without accessing ring state. */
void virtqueue_handle_notification(struct virtqueue *vq)
{
	if (vq->callback)
		vq->callback(vq);
}

TEE_Result virtio_queue_attach(struct virtio_device *vdev,
			       struct virtqueue *vq)
{
	struct virtqueue *other_vq = NULL;

	TAILQ_FOREACH(other_vq, &vdev->queues, link)
		if (other_vq->qid == vq->qid)
			return TEE_ERROR_ACCESS_CONFLICT;

	vq->vdev = vdev;
	TAILQ_INSERT_TAIL(&vdev->queues, vq, link);

	return TEE_SUCCESS;
}

TEE_Result virtio_queue_detach(struct virtqueue *vq)
{
	const uint8_t setup = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
			      VIRTIO_STATUS_FEATURES_OK;
	uint8_t status = 0;
	TEE_Result res = TEE_SUCCESS;

	/* Outstanding requests must be completed or cancelled first. */
	if (vq->inflight)
		return TEE_ERROR_BUSY;

	/* Without confirmed reset, permit only pre-DRIVER_OK setup rollback. */
	if (!vq->stopped) {
		res = vq->vdev->ops->get_status(vq->vdev, &status);
		if (res)
			return res;
		if (status != setup)
			return TEE_ERROR_BUSY;
	}

	TAILQ_REMOVE(&vq->vdev->queues, vq, link);

	return TEE_SUCCESS;
}


