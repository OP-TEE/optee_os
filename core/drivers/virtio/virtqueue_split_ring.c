// SPDX-License-Identifier: BSD-2-Clause
#include <drivers/virtio.h>
#include <drivers/virtio_ring.h>
#include <io.h>
#include <kernel/tee_misc.h>
#include <malloc.h>
#include <string.h>
#include <util.h>

#include "virtio_private.h"

#define VIRTQUEUE_DESC_NONE		UINT16_MAX

static struct virtqueue *allocate_queue(uint16_t size)
{
	struct virtqueue *vq = NULL;
	struct virtqueue_split_ring *split_ring = NULL;
	uint16_t n = 0;

	vq = calloc(1, sizeof(*vq));
	if (!vq)
		return NULL;

	split_ring = &vq->split_ring;
	split_ring->desc_state = calloc(size, sizeof(*split_ring->desc_state));
	if (!split_ring->desc_state)
		goto err;

	split_ring->desc_regions =
		calloc(size, sizeof(*split_ring->desc_regions));
	if (!split_ring->desc_regions)
		goto err;

	vq->size = size;
	/* Link all descriptors into the initial free list. */
	split_ring->num_free = size;
	for (n = 0; n < size; n++)
		split_ring->desc_state[n].next = n + 1;
	split_ring->desc_state[size - 1].next = VIRTQUEUE_DESC_NONE;

	return vq;

err:
	free(split_ring->desc_regions);
	free(split_ring->desc_state);
	free(vq);

	return NULL;
}

TEE_Result
virtqueue_create(struct virtio_device *vdev, uint16_t qid, uint16_t size,
		 const struct vring_split_regions *regions,
		 TEE_Result (*kick)(struct virtqueue *vq),
		 void (*callback)(struct virtqueue *vq),
		 struct virtqueue **vqp)
{
	struct virtqueue *vq = NULL;
	size_t desc_size = 0;
	size_t avail_size = 0;
	size_t used_size = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!kick)
		return TEE_ERROR_BAD_PARAMETERS;

	res = vring_split_sizes(size, &desc_size, &avail_size, &used_size);
	if (res)
		return res;

	if (regions->desc.size < desc_size ||
	    regions->avail.size < avail_size ||
	    regions->used.size < used_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!regions->desc.va || !regions->avail.va || !regions->used.va)
		return TEE_ERROR_BAD_PARAMETERS;
	/* Check local ring addresses meet split-ring alignment requirements. */
	if (!IS_ALIGNED((uintptr_t)regions->desc.va, VRING_DESC_ALIGN_SIZE) ||
	    !IS_ALIGNED((uintptr_t)regions->avail.va, VRING_AVAIL_ALIGN_SIZE) ||
	    !IS_ALIGNED((uintptr_t)regions->used.va, VRING_USED_ALIGN_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	vq = allocate_queue(size);
	if (!vq)
		return TEE_ERROR_OUT_OF_MEMORY;

	vq->qid = qid;
	vq->kick = kick;
	vq->callback = callback;
	vq->split_ring.regions = *regions;

	res = virtio_queue_attach(vdev, vq);
	if (res)
		goto err;

	memset(regions->desc.va, 0, desc_size);
	memset(regions->avail.va, 0, avail_size);
	memset(regions->used.va, 0, used_size);
	virtio_mb();
	*vqp = vq;

	return TEE_SUCCESS;

err:
	free(vq->split_ring.desc_regions);
	free(vq->split_ring.desc_state);
	free(vq);

	return res;
}

TEE_Result virtqueue_destroy(struct virtqueue *vq)
{
	struct virtqueue_split_ring *split_ring = &vq->split_ring;
	TEE_Result res = TEE_SUCCESS;

	res = virtio_queue_detach(vq);
	if (res)
		return res;
	free(split_ring->desc_regions);
	free(split_ring->desc_state);
	free(vq);

	return TEE_SUCCESS;
}

struct virtio_device *virtqueue_get_device(struct virtqueue *vq)
{
	return vq->vdev;
}

uint16_t virtqueue_get_qid(struct virtqueue *vq)
{
	return vq->qid;
}

static void unmap_descriptor(struct virtqueue *vq, uint16_t id)
{
	struct virtqueue_split_ring *split_ring = &vq->split_ring;

	if (split_ring->desc_state[id].mapped) {
		vq->vdev->map_ops->release(vq->vdev,
					     &split_ring->desc_regions[id]);
		split_ring->desc_state[id].mapped = false;
		split_ring->desc_regions[id] = (struct virtio_mem_region){ };
	}
}

/* @out_count outgoing buffers come first, then @in_count incoming buffers. */
TEE_Result
virtqueue_add_sgs(struct virtqueue *vq, const struct virtio_sg *segments,
		  size_t out_count, size_t in_count, void *token)
{
	struct virtqueue_split_ring *split_ring = NULL;
	struct vring_desc *desc = NULL;
	struct vring_avail *avail = NULL;
	uint16_t slot = 0;
	uint64_t writable = 0;
	uint16_t head = 0;
	uint16_t id = 0;
	uint16_t last = 0;
	uint16_t next = 0;
	size_t count = out_count + in_count;
	size_t n = 0;
	size_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!token)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!virtqueue_is_usable(vq))
		return TEE_ERROR_BAD_STATE;

	if (!count || count > vq->size)
		return TEE_ERROR_BAD_PARAMETERS;

	split_ring = &vq->split_ring;
	if (count > split_ring->num_free)
		return TEE_ERROR_BUSY;

	for (n = out_count; n < count; n++)
		writable += segments[n].size;

	desc = vring_split_get_desc(&split_ring->regions);
	avail = vring_split_get_avail(&split_ring->regions);
	head = split_ring->free_head;
	/* Map each buffer and build its descriptor using the free list. */
	for (n = 0, id = head; n < count; n++, id = next) {
		struct virtqueue_split_desc_state *state =
			&split_ring->desc_state[id];
		struct virtio_mem_region *region =
			&split_ring->desc_regions[id];

		uint32_t size = segments[n].size;
		bool write = n >= out_count;
		uint64_t address = 0;
		uint16_t flags = write ? VRING_DESC_F_WRITE : 0;

		next = state->next;

		if (size) {
			enum virtio_memory_access access =
				write ? VIRTIO_MEMORY_WRITE :
					VIRTIO_MEMORY_READ;

			res = vq->vdev->map_ops->map(vq->vdev,
						     segments[n].data, size,
						     access, region);
			if (res)
				goto unmap_buffers;

			state->mapped = true;
			address = region->address;
		}

		desc[id].addr = TEE_U64_TO_LITTLE_ENDIAN(address);
		desc[id].len = TEE_U32_TO_LITTLE_ENDIAN(size);
		/* All but the last descriptor link to the next. */
		if (n + 1 < count)
			flags |= VRING_DESC_F_NEXT;
		desc[id].flags = TEE_U16_TO_LITTLE_ENDIAN(flags);
		desc[id].next = TEE_U16_TO_LITTLE_ENDIAN(next);

		last = id;
	}

	/* End the request chain and advance the free list past it. */
	split_ring->desc_state[last].next = VIRTQUEUE_DESC_NONE;
	split_ring->free_head = id;
	split_ring->num_free -= count;

	vq->inflight++;
	split_ring->desc_state[head].token = token;
	split_ring->desc_state[head].writable = writable;
	slot = split_ring->last_avail_idx & (vq->size - 1);
	avail->ring[slot] = TEE_U16_TO_LITTLE_ENDIAN(head);
	/* Publish descriptors, payload and head before the available index. */
	virtio_mb();
	split_ring->last_avail_idx++;
	WRITE_ONCE(avail->idx,
		   TEE_U16_TO_LITTLE_ENDIAN(split_ring->last_avail_idx));

	return TEE_SUCCESS;

unmap_buffers:
	/* Release attempted mappings using the unchanged private free links. */
	for (i = 0, id = head; i <= n; i++) {
		unmap_descriptor(vq, id);
		id = split_ring->desc_state[id].next;
	}

	return res;
}

TEE_Result virtqueue_kick(struct virtqueue *vq)
{
	struct vring_used *used = NULL;
	TEE_Result res = TEE_SUCCESS;

	/* The class calls this only after DRIVER_OK and excludes teardown. */
	if (!virtqueue_is_usable(vq))
		return TEE_ERROR_BAD_STATE;

	used = vring_split_get_used(&vq->split_ring.regions);
	/* Order index publication before inspecting device suppression. */
	virtio_mb();
	if (TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(used->flags)) &
	    VRING_USED_F_NO_NOTIFY)
		return TEE_SUCCESS;

	res = vq->kick(vq);
	if (res)
		vq->broken = true;

	return res;
}

static void release_descriptor_chain(struct virtqueue *vq, uint16_t head)
{
	struct virtqueue_split_ring *split_ring = &vq->split_ring;
	uint16_t id = 0;
	uint16_t last = 0;

	for (id = head; id != VIRTQUEUE_DESC_NONE;
	     id = split_ring->desc_state[id].next) {
		unmap_descriptor(vq, id);
		split_ring->num_free++;
		last = id;
	}

	split_ring->desc_state[last].next = split_ring->free_head;
	split_ring->free_head = head;
	split_ring->desc_state[head].token = NULL;

	vq->inflight--;
}

/* On success, return one completion from @vq in @token and @written. */
TEE_Result virtqueue_get_used(struct virtqueue *vq, void **token,
			      uint32_t *written)
{
	struct virtqueue_split_ring *split_ring = NULL;
	struct virtqueue_split_desc_state *state = NULL;
	struct vring_used *used = NULL;
	struct vring_used_elem *elem = NULL;
	uint16_t count = 0;
	uint32_t id = 0;
	uint32_t len = 0;

	if (!virtqueue_is_usable(vq))
		return TEE_ERROR_BAD_STATE;

	split_ring = &vq->split_ring;
	used = vring_split_get_used(&vq->split_ring.regions);
	/* Count unconsumed completions with 16-bit index wraparound. */
	count = TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(used->idx)) -
		  split_ring->last_used_idx;
	if (!count)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (count > vq->inflight)
		goto invalid_completion;

	/* Device publishes payload and used entries before its index. */
	virtio_mb();
	elem = &used->ring[split_ring->last_used_idx & (vq->size - 1)];
	id = TEE_U32_FROM_LITTLE_ENDIAN(READ_ONCE(elem->id));
	len = TEE_U32_FROM_LITTLE_ENDIAN(READ_ONCE(elem->len));
	if (id >= vq->size)
		goto invalid_completion;

	state = &split_ring->desc_state[id];
	if (!state->token || len > state->writable)
		goto invalid_completion;

	*token = state->token;
	*written = len;
	release_descriptor_chain(vq, id);
	split_ring->last_used_idx++;

	return TEE_SUCCESS;

invalid_completion:
	vq->broken = true;

	return TEE_ERROR_SECURITY;
}

TEE_Result
virtqueue_set_notifications(struct virtqueue *vq, bool enable, bool *pending)
{
	struct virtqueue_split_ring *split_ring = NULL;
	struct vring_avail *avail = NULL;
	struct vring_used *used = NULL;
	uint16_t flags = enable ? 0 : VRING_AVAIL_F_NO_INTERRUPT;

	*pending = false;

	if (!virtqueue_is_usable(vq))
		return TEE_ERROR_BAD_STATE;

	split_ring = &vq->split_ring;
	avail = vring_split_get_avail(&vq->split_ring.regions);
	used = vring_split_get_used(&vq->split_ring.regions);
	WRITE_ONCE(avail->flags, TEE_U16_TO_LITTLE_ENDIAN(flags));
	virtio_mb();

	*pending = TEE_U16_FROM_LITTLE_ENDIAN(READ_ONCE(used->idx)) !=
		   split_ring->last_used_idx;

	return TEE_SUCCESS;
}

TEE_Result virtqueue_cancel(struct virtqueue *vq, void **token)
{
	struct virtqueue_split_ring *split_ring = NULL;
	uint16_t id = 0;

	*token = NULL;

	if (!vq->stopped)
		return TEE_ERROR_BAD_STATE;

	split_ring = &vq->split_ring;
	while (split_ring->cancel_id < vq->size) {
		id = split_ring->cancel_id++;
		if (split_ring->desc_state[id].token) {
			*token = split_ring->desc_state[id].token;
			release_descriptor_chain(vq, id);

			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

