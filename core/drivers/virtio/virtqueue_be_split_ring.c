// SPDX-License-Identifier: BSD-2-Clause
#include <assert.h>
#include <drivers/virtio_be.h>
#include <io.h>
#include <malloc.h>
#include <string.h>
#include <util.h>

#include "virtio_be_private.h"

TEE_Result
virtqueue_be_bind(struct virtqueue_be *vq,
		  const struct virtio_queue_config *qinfo)
{
	struct virtio_be_dev *vbe_dev = vq->vbe_dev;
	struct virtqueue_be_split_ring split_ring = { };
	struct virtio_be_segment *segments = NULL;
	size_t desc_size = 0;
	size_t avail_size = 0;
	size_t used_size = 0;
	TEE_Result res = TEE_SUCCESS;

	/* A nonzero size means the queue is already bound. */
	if (vq->size)
		return TEE_ERROR_BAD_STATE;
	/* The selected queue size must not exceed the device class limit. */
	if (qinfo->size > vbe_dev->type->max_queue_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = vring_split_sizes(qinfo->size, &desc_size, &avail_size,
				&used_size);
	if (res)
		return res;

	/* Pin desc [qinfo->desc, desc_size], DESC_ALIGN, MEMORY_READ. */
	res = virtio_be_dev_map_region(vbe_dev, qinfo->desc, desc_size,
				       VRING_DESC_ALIGN_SIZE,
				       VIRTIO_MEMORY_READ,
				       &split_ring.regions.desc);
	if (res)
		return res;
	/* Pin avail [qinfo->avail, avail_size], AVAIL_ALIGN, MEMORY_READ. */
	res = virtio_be_dev_map_region(vbe_dev, qinfo->avail, avail_size,
				       VRING_AVAIL_ALIGN_SIZE,
				       VIRTIO_MEMORY_READ,
				       &split_ring.regions.avail);
	if (res)
		goto release_desc;
	/* Pin used [qinfo->used, used_size], USED_ALIGN, MEMORY_WRITE. */
	res = virtio_be_dev_map_region(vbe_dev, qinfo->used, used_size,
				       VRING_USED_ALIGN_SIZE,
				       VIRTIO_MEMORY_WRITE,
				       &split_ring.regions.used);
	if (res)
		goto release_avail;

	segments = calloc(qinfo->size, sizeof(*segments));
	if (!segments) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto release_used;
	}

	vq->split_ring = split_ring;
	vq->size = qinfo->size;
	vq->request = (struct virtio_be_request){
		.segments = segments,
	};

	return TEE_SUCCESS;

release_used:
	virtio_be_dev_unmap_region(vbe_dev, &split_ring.regions.used);
release_avail:
	virtio_be_dev_unmap_region(vbe_dev, &split_ring.regions.avail);
release_desc:
	virtio_be_dev_unmap_region(vbe_dev, &split_ring.regions.desc);

	return res;
}

/* Release rings and segments of a stopped, drained queue. */
void virtqueue_be_unbind(struct virtqueue_be *vq)
{
	struct virtio_be_dev *vbe_dev = vq->vbe_dev;
	struct virtqueue_be_split_ring *split_ring = &vq->split_ring;

	if (!vq->size)
		return;

	virtio_be_dev_unmap_region(vbe_dev, &split_ring->regions.used);
	virtio_be_dev_unmap_region(vbe_dev, &split_ring->regions.avail);
	virtio_be_dev_unmap_region(vbe_dev, &split_ring->regions.desc);

	free(vq->request.segments);
	/* Mark the queue as unbound. */
	vq->size = 0;
	vq->notify = NULL;
}

struct virtio_be_dev *virtqueue_be_get_device(struct virtqueue_be *vq)
{
	return vq->vbe_dev;
}

uint16_t virtqueue_be_get_qid(struct virtqueue_be *vq)
{
	return vq->qid;
}

/* Lock a running queue for class processing; otherwise TEE_ERROR_BAD_STATE. */
TEE_Result virtio_be_dev_lock_queue(struct virtio_be_dev *vbe_dev, uint16_t qid,
				    struct virtqueue_be **vqp)
{
	struct virtqueue_be *vq = NULL;

	if (qid >= vbe_dev->type->queue_count)
		return TEE_ERROR_BAD_PARAMETERS;

	vq = &vbe_dev->queues[qid];
	mutex_lock(&vq->mutex);
	if (!virtqueue_be_running(vq)) {
		mutex_unlock(&vq->mutex);

		return TEE_ERROR_BAD_STATE;
	}

	*vqp = vq;

	return TEE_SUCCESS;
}

void virtqueue_be_unlock(struct virtqueue_be *vq)
{
	mutex_unlock(&vq->mutex);
}

/* Validate that the request has a bound queue and a current chain. */
static TEE_Result validate_request_state(struct virtio_be_request *req)
{
	struct virtqueue_be *vq = NULL;

	if (!req)
		return TEE_ERROR_BAD_PARAMETERS;

	vq = container_of(req, struct virtqueue_be, request);
	if (!vq->size || !req->count)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

/* @write specifies the direction to/from the request. */
static TEE_Result copy_request_data(struct virtio_be_request *req, void *buffer,
				    size_t size, size_t *copied, bool write)
{
	struct virtio_be_cursor *cursor = NULL;
	uint32_t written = 0;
	size_t done = 0;
	TEE_Result res = TEE_SUCCESS;

	res = validate_request_state(req);
	if (res)
		return res;

	if (write) {
		/* Check overflow only for bytes that can actually be copied. */
		size = MIN(size, req->writable_remaining);
		if (ADD_OVERFLOW(req->written, size, &written))
			return TEE_ERROR_OVERFLOW;
		cursor = &req->write_cursor;
	} else {
		cursor = &req->read_cursor;
	}

	while (cursor->segment < req->count && done < size) {
		struct virtio_be_segment *s = &req->segments[cursor->segment];
		uint8_t *data = NULL;
		size_t copy_size = 0;

		/* Readable segments end where writable segments begin. */
		if (s->writable != write)
			break;
		/* Advance past exhausted or zero-length segments. */
		if (cursor->offset == s->size) {
			cursor->segment++;
			cursor->offset = 0;
			continue;
		}

		/* Copy as much as possible to/from current segment: */
		copy_size = MIN(size - done, s->size - cursor->offset);
		data = (uint8_t *)s->mapping.va + cursor->offset;
		if (write)
			memcpy(data, (uint8_t *)buffer + done, copy_size);
		else
			memcpy((uint8_t *)buffer + done, data, copy_size);

		done += copy_size;
		cursor->offset += copy_size;
	}

	if (write) {
		req->writable_remaining -= done;
		req->written += done;
	} else {
		req->readable_remaining -= done;
	}

	*copied = done;

	return TEE_SUCCESS;
}

TEE_Result virtio_be_request_copy_from(struct virtio_be_request *req,
				       void *buffer, size_t size,
				       size_t *copied)
{
	return copy_request_data(req, buffer, size, copied, false);
}

TEE_Result virtio_be_request_copy_to(struct virtio_be_request *req,
				     const void *buffer, size_t size,
				     size_t *copied)
{
	return copy_request_data(req, (void *)buffer, size, copied, true);
}

/* Count unconsumed available entries and reject counts exceeding queue size. */
static TEE_Result available_count(struct virtqueue_be *vq,
				  uint16_t *count)
{
	struct vring_avail *avail =
		vring_split_get_avail(&vq->split_ring.regions);
	uint16_t idx = TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(avail->idx));

	*count = idx - vq->split_ring.last_avail_idx;
	if (*count > vq->size)
		return TEE_ERROR_SECURITY;
	/* Order reads of published entries and buffers after the index read. */
	if (*count)
		virtio_mb();

	return TEE_SUCCESS;
}

/* Save and validate the next descriptor chain. */
static TEE_Result parse_request_chain(struct virtqueue_be *vq,
				      struct virtio_be_request *req)
{
	struct vring_desc *desc = vring_split_get_desc(&vq->split_ring.regions);
	struct vring_avail *avail =
		vring_split_get_avail(&vq->split_ring.regions);
	/* Wrap the available index to a slot in the power-of-two ring. */
	uint16_t slot = vq->split_ring.last_avail_idx & (vq->size - 1);
	uint16_t id = TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(avail->ring[slot]));
	bool writing = false;
	uint64_t total = 0;

	req->count = 0;
	req->readable_remaining = 0;
	req->writable_remaining = 0;
	req->written = 0;
	req->head = id;
	req->read_cursor = (struct virtio_be_cursor){ };
	req->write_cursor = (struct virtio_be_cursor){ };

	while (req->count < vq->size) {
		struct virtio_be_segment *s = NULL;
		uint16_t flags = 0;

		if (id >= vq->size)
			return TEE_ERROR_SECURITY;

		flags = TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(desc[id].flags));

		s = &req->segments[req->count];
		s->address =
			TEE_U64_FROM_LITTLE_ENDIAN(READ_ONCE(desc[id].addr));
		s->size = TEE_U32_FROM_LITTLE_ENDIAN(READ_ONCE(desc[id].len));
		s->writable = flags & VRING_DESC_F_WRITE;

		/* Reject unsupported flags. */
		if ((flags & ~(VRING_DESC_F_NEXT | VRING_DESC_F_WRITE)))
			return TEE_ERROR_SECURITY;
		/* Reject readable segments after writable ones. */
		if (!s->writable && writing)
			return TEE_ERROR_SECURITY;

		/* Start the write cursor at the first writable segment. */
		if (s->writable && !writing)
			req->write_cursor.segment = req->count;

		writing |= s->writable;

		total += s->size;
		/* A descriptor chain must not exceed 2^32 bytes. */
		if (total > BIT64(32))
			return TEE_ERROR_SECURITY;

		if (s->writable)
			req->writable_remaining += s->size;
		else
			req->readable_remaining += s->size;

		req->count++;
		if (!(flags & VRING_DESC_F_NEXT)) {
			if (!writing)
				req->write_cursor.segment = req->count;

			return TEE_SUCCESS;
		}

		/* VRING_DESC_F_NEXT is set: */
		id = TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(desc[id].next));
	}

	return TEE_ERROR_SECURITY;
}

static void unpin_request(struct virtqueue_be *vq,
			  struct virtio_be_request *req)
{
	struct virtio_be_segment *s =  NULL;
	uint16_t n = 0;

	for (n = req->count; n; n--) {
		s = &req->segments[n - 1];
		if (s->pinned) {
			virtio_be_dev_unmap_region(vq->vbe_dev, &s->mapping);
			s->pinned = false;
		}
	}
}

static TEE_Result pin_request(struct virtqueue_be *vq,
			      struct virtio_be_request *req)
{
	struct virtio_be_segment *s = NULL;
	enum virtio_memory_access access = VIRTIO_MEMORY_READ;
	uint16_t n = 0;
	TEE_Result res = TEE_SUCCESS;

	for (n = 0; n < req->count; n++) {
		s = &req->segments[n];
		if (!s->size)
			continue;
		if (s->writable)
			access = VIRTIO_MEMORY_WRITE;

		res = virtio_be_dev_map_region(vq->vbe_dev, s->address,
					       s->size, 1, access, &s->mapping);
		if (res)
			return res;

		s->pinned = true;
	}

	return TEE_SUCCESS;
}

TEE_Result virtqueue_be_get_request(struct virtqueue_be *vq,
				    struct virtio_be_request **reqp)
{
	struct virtio_be_request *req = NULL;
	uint16_t count = 0;
	TEE_Result res = TEE_SUCCESS;

	/* Reject stopped queues or an outstanding borrowed request. */
	if (!virtqueue_be_running(vq) || vq->request.count)
		return TEE_ERROR_BAD_STATE;

	res = available_count(vq, &count);
	if (res || !count) {
		if (!res)
			res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	req = &vq->request;
	res = parse_request_chain(vq, req);
	if (!res)
		res = pin_request(vq, req);
	if (res) {
		if (res == TEE_ERROR_ACCESS_DENIED ||
		    res == TEE_ERROR_BAD_PARAMETERS ||
		    res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_ERROR_SECURITY;
		unpin_request(vq, req);
		req->count = 0;
		goto out;
	}

	vq->split_ring.last_avail_idx++;

	*reqp = req;

out:
	if (res == TEE_ERROR_SECURITY)
		virtio_be_dev_needs_reset(vq->vbe_dev);

	return res;
}

TEE_Result virtio_be_request_remaining(struct virtio_be_request *req,
				       uint64_t *readable, uint64_t *writable)
{
	TEE_Result res = TEE_SUCCESS;

	res = validate_request_state(req);
	if (res)
		return res;

	*readable = req->readable_remaining;
	*writable = req->writable_remaining;

	return TEE_SUCCESS;
}

/* Complete or cancel the request, release mappings and clear @reqp. */
static TEE_Result finish_request(struct virtio_be_request **reqp, bool cancel)
{
	struct virtio_be_request *req = NULL;
	struct virtqueue_be *vq = NULL;
	struct virtqueue_be_split_ring *split_ring = NULL;
	TEE_Result res = TEE_SUCCESS;

	req = *reqp;
	res = validate_request_state(req);
	if (res)
		return res;

	vq = container_of(req, struct virtqueue_be, request);
	split_ring = &vq->split_ring;

	if (!cancel) {
		struct vring_used *used =
			vring_split_get_used(&vq->split_ring.regions);
		/* Wrap the used index to a slot in the power-of-two ring. */
		uint16_t slot = split_ring->last_used_idx & (vq->size - 1);
		struct vring_used_elem *elem = &used->ring[slot];

		elem->id = TEE_U32_TO_LITTLE_ENDIAN(req->head);
		elem->len = TEE_U32_TO_LITTLE_ENDIAN(req->written);
		virtio_mb();

		split_ring->last_used_idx++;
		WRITE_ONCE(used->idx,
			   TEE_U16_TO_LITTLE_ENDIAN(split_ring->last_used_idx));
	} else {
		virtio_be_dev_needs_reset(vq->vbe_dev);
	}

	unpin_request(vq, req);
	req->count = 0;

	*reqp = NULL;

	return TEE_SUCCESS;
}

TEE_Result virtio_be_request_complete(struct virtio_be_request **reqp)
{
	return finish_request(reqp, false);
}

TEE_Result virtio_be_request_cancel(struct virtio_be_request **reqp)
{
	return finish_request(reqp, true);
}

TEE_Result virtqueue_be_set_kicks(struct virtqueue_be *vq, bool enable,
				  bool *pending)
{
	struct vring_used *used = NULL;
	uint16_t count = 0;
	TEE_Result res = TEE_SUCCESS;

	*pending = false;

	if (!virtqueue_be_running(vq))
		return TEE_ERROR_BAD_STATE;

	used = vring_split_get_used(&vq->split_ring.regions);
	WRITE_ONCE(used->flags,
		   TEE_U16_TO_LITTLE_ENDIAN(enable ? 0 :
					    VRING_USED_F_NO_NOTIFY));
	virtio_mb();

	res = available_count(vq, &count);
	if (res)
		virtio_be_dev_needs_reset(vq->vbe_dev);
	else
		*pending = count;

	return res;
}

TEE_Result virtqueue_be_notify(struct virtqueue_be *vq)
{
	struct vring_avail *avail = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (!vq->size)
		return TEE_ERROR_BAD_STATE;

	avail = vring_split_get_avail(&vq->split_ring.regions);
	/* Order used-ring updates before reading notification suppression. */
	virtio_mb();
	if (!(TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(avail->flags)) &
	      VRING_AVAIL_F_NO_INTERRUPT) && vq->notify)
		res = vq->notify(vq);

	if (res)
		virtio_be_dev_needs_reset(vq->vbe_dev);

	return res;
}
