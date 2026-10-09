/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Sharan Santhanam <sharan.santhanam@neclab.eu>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * Inspired from the FreeBSD.
 * Commit-id: a89e7a10d501
 */

#include <string.h>

#include <uk/arch/util.h>
#include <uk/atomic.h>
#include <uk/config.h>
#include <uk/errptr.h>
#include <uk/paging.h>
#include <uk/print.h>
#include <uk/sglist.h>

#include <virtio/virtio_ring.h>
#include <virtio/virtqueue.h>
#include <virtio/virtio_bus.h>

#if CONFIG_LIBVIRTIO_SNP_DMA
#include <uk/plat/shmem.h>
#endif

#ifdef CONFIG_LIBUKVMEM
#include <uk/falloc.h>
#include <uk/vmem.h>
#endif /* CONFIG_LIBUKVMEM */

#define VIRTQUEUE_MAX_SIZE  32768
#define to_virtqueue_vring(vq)			\
	__containerof(vq, struct virtqueue_vring, vq)

struct virtqueue_desc_info {
	void *cookie;
	__u16 desc_count;
#if CONFIG_LIBVIRTIO_SNP_DMA
	__paddr_t private_pa;
	__u32 dma_len;
	__u16 next;
	__u8 writable;
#endif
};

struct virtqueue_vring {
	struct virtqueue vq;
	/* Descriptor Ring */
	struct vring vring;
	/* Reference to the vring */
	void   *vring_mem;
	/* Keep track of available descriptors */
	__u16 desc_avail;
	/* Index of the next available slot */
	__u16 head_free_desc;
	/* Index of the last used descriptor by the host */
	__u16 last_used_desc_idx;
	/* EVENT_IDX notification suppression is used */
	__u8 uses_event_idx;
	/* EVENT_IDX last notified idx */
	__u16 last_notified_idx;
#if CONFIG_LIBVIRTIO_SNP_DMA
	void *dma_pool;
	__u16 private_avail_idx;
#endif
	/* Cookie to identify driver buffer */
	struct virtqueue_desc_info vq_info[];
};

#if CONFIG_LIBVIRTIO_SNP_DMA
static int virtqueue_dma_copy(__paddr_t pa, void *bounce, __u32 len,
			     int to_device)
{
	struct uk_pagetable *pt = uk_paging_pt_get_active();
	__vaddr_t va;
	__sz offset = pa & (__PAGE_SIZE - 1);

	va = uk_paging_page_kmap(pt, pa - offset, 1, 0);
	if (va == UK_PAGING_VADDR_INV)
		return -ENOMEM;
	if (to_device)
		memcpy(bounce, (void *)(va + offset), len);
	else
		memcpy((void *)(va + offset), bounce, len);
	uk_paging_page_kunmap(pt, va, 1, 0);
	return 0;
}

static int virtqueue_dma_desc_count(struct uk_sglist *sg, __u16 count,
				   __u16 capacity)
{
	__sz total = 0;
	__sz len, offset;
	unsigned int i;

	for (i = 0; i < count; i++) {
		len = sg->sg_segs[i].ss_len;
		offset = sg->sg_segs[i].ss_paddr & (__PAGE_SIZE - 1);
		if (!len || len > (__sz)capacity * __PAGE_SIZE)
			return -ENOSPC;
		total += (offset + len + __PAGE_SIZE - 1) / __PAGE_SIZE;
		if (total > capacity)
			return -ENOSPC;
	}
	return (int)total;
}

static int virtqueue_dma_enqueue(struct virtqueue_vring *vrq, __u16 head,
				struct uk_sglist *sg, __u16 read_bufs,
				__u16 write_bufs, __u16 count)
{
	__u16 idx = head, remaining = count;
	unsigned int i;
	__paddr_t pa;
	__sz len;
	__u32 part;
	void *bounce;
	struct virtqueue_desc_info *info;
	int rc;

	for (i = 0; i < (unsigned int)read_bufs + write_bufs; i++) {
		pa = sg->sg_segs[i].ss_paddr;
		len = sg->sg_segs[i].ss_len;
		while (len) {
			part = MIN(len, __PAGE_SIZE - (pa & (__PAGE_SIZE - 1)));
			info = &vrq->vq_info[idx];
			bounce = (char *)vrq->dma_pool + (__sz)idx * __PAGE_SIZE;
			memset(bounce, 0, __PAGE_SIZE);
			if (i < read_bufs) {
				rc = virtqueue_dma_copy(pa, bounce, part, 1);
				if (rc)
					return rc;
			}
			info->private_pa = pa;
			info->dma_len = part;
			info->writable = i >= read_bufs;
			vrq->vring.desc[idx].addr = ukplat_shmem_gpa(bounce);
			vrq->vring.desc[idx].len = part;
			vrq->vring.desc[idx].next = info->next;
			vrq->vring.desc[idx].flags =
				(info->writable ? VRING_DESC_F_WRITE : 0) |
				(--remaining ? VRING_DESC_F_NEXT : 0);
			idx = info->next;
			pa += part;
			len -= part;
		}
	}
	return idx;
}

static int virtqueue_dma_complete(struct virtqueue_vring *vrq, __u32 head,
				 __u32 len)
{
	__u32 capacity = 0, part;
	__u16 idx, count, i;
	struct virtqueue_desc_info *info;
	void *bounce;
	int rc;

	if (head >= vrq->vring.num || !vrq->vq_info[head].cookie)
		return -EIO;
	count = vrq->vq_info[head].desc_count;
	for (i = 0, idx = head; i < count; i++) {
		info = &vrq->vq_info[idx];
		if (info->writable)
			capacity += info->dma_len;
		idx = info->next;
	}
	if (len > capacity)
		return -EIO;
	for (i = 0, idx = head; i < count; i++) {
		info = &vrq->vq_info[idx];
		bounce = (char *)vrq->dma_pool + (__sz)idx * __PAGE_SIZE;
		if (info->writable && len) {
			part = MIN(len, info->dma_len);
			rc = virtqueue_dma_copy(info->private_pa, bounce, part, 0);
			if (rc)
				return rc;
			len -= part;
		}
		memset(bounce, 0, __PAGE_SIZE);
		idx = info->next;
	}
	return 0;
}
#endif

/**
 * Static function Declaration(s).
 */
static inline void virtqueue_ring_update_avail(struct virtqueue_vring *vrq,
					       __u16 idx);
static inline void virtqueue_detach_desc(struct virtqueue_vring *vrq,
					 __u16 head_idx);
static inline int virtqueue_buffer_enqueue_segments(
						    struct virtqueue_vring *vrq,
						    __u16 head,
						    struct uk_sglist *sg,
						    __u16 read_bufs,
						    __u16 write_bufs);
static void virtqueue_vring_init(struct virtqueue_vring *vrq, __u16 nr_desc,
				 __u16 align);

/**
 * Driver implementation
 */
void virtqueue_intr_disable(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);

	if (vrq->uses_event_idx) {
		vring_used_event(&vrq->vring) =
			vrq->last_used_desc_idx - vrq->vring.num - 1;
		return;
	}
	vrq->vring.avail->flags |= (VRING_AVAIL_F_NO_INTERRUPT);
}

int virtqueue_intr_enable(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq;
	int rc = 0;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
	/* Check if there are no more packets enabled */
	if (!virtqueue_hasdata(vq)) {
		if (vrq->uses_event_idx) {
			/* TODO: This allows delaying the interrupts by a
			 *       adjustable count of descriptors. This is could
			 *       be useful for TXQ interrupts, which can be
			 *       handled in a batched fashion.
			 */
			vring_used_event(&vrq->vring) =
			    vrq->last_used_desc_idx + 0;
		} else {
			vrq->vring.avail->flags &=
				(~VRING_AVAIL_F_NO_INTERRUPT);
		}

		/**
		 * We enabled the interrupts. We ensure it using the
		 * memory barrier and check if there are any further
		 * data available in the queue. The check for data
		 * after enabling the interrupt is to make sure we do
		 * not miss any interrupt while transitioning to enable
		 * interrupt. This is inline with the requirement from
		 * virtio specification section 3.2.2
		 */
		uk_arch_mb();
		/* Check if there are further descriptors */
		if (virtqueue_hasdata(vq)) {
			virtqueue_intr_disable(vq);
			rc = 1;
		}
	} else {
		/**
		 * There are more packet in the virtqueue to be processed while
		 * the interrupt was disabled.
		 */
		rc = 1;
	}
	return rc;
}

static inline void virtqueue_ring_update_avail(struct virtqueue_vring *vrq,
					__u16 idx)
{
	__u16 avail_idx;

#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool)
		avail_idx = vrq->private_avail_idx & (vrq->vring.num - 1);
	else
#endif
		avail_idx = vrq->vring.avail->idx & (vrq->vring.num - 1);
	/* Adding the idx to available ring */
	vrq->vring.avail->ring[avail_idx] = idx;
	/**
	 * Write barrier to make sure we push the descriptor on the available
	 * descriptor and then increment available index.
	 */
	uk_arch_wmb();
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool)
		vrq->vring.avail->idx = ++vrq->private_avail_idx;
	else
#endif
		vrq->vring.avail->idx++;
}

static inline void virtqueue_detach_desc(struct virtqueue_vring *vrq,
					__u16 head_idx)
{
	struct vring_desc *desc;
	struct virtqueue_desc_info *vq_info;

#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool) {
		__u16 idx = head_idx, i;

		vq_info = &vrq->vq_info[head_idx];
		vrq->desc_avail += vq_info->desc_count;
		for (i = 1; i < vq_info->desc_count; i++)
			idx = vrq->vq_info[idx].next;
		vrq->vq_info[idx].next = vrq->head_free_desc;
		vrq->head_free_desc = head_idx;
		vq_info->desc_count = 0;
		return;
	}
#endif

	desc = &vrq->vring.desc[head_idx];
	vq_info = &vrq->vq_info[head_idx];
	vrq->desc_avail += vq_info->desc_count;
	vq_info->desc_count--;

	while (desc->flags & VRING_DESC_F_NEXT) {
		desc = &vrq->vring.desc[desc->next];
		vq_info->desc_count--;
	}

	/* The value should be empty */
	UK_ASSERT(vq_info->desc_count == 0);

	/* Appending the descriptor to the head of list */
	desc->next = vrq->head_free_desc;
	vrq->head_free_desc = head_idx;
}

static int virtqueue_notify_enabled(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq;
	__u16 old, new;

	UK_ASSERT(vq);
	vrq = to_virtqueue_vring(vq);
	if (vrq->uses_event_idx) {
		new = vrq->vring.avail->idx;
		old = vrq->last_notified_idx;

		return vring_need_event(vring_avail_event(&vrq->vring),
					new, old);
	}

	return ((vrq->vring.used->flags & VRING_USED_F_NO_NOTIFY) == 0);
}

void virtqueue_host_notify(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);

	/*
	 * Before notifying the virtio backend on the host we should make sure
	 * that the virtqueue index update operation happened. Note that this
	 * function is declared as inline.
	 */
	uk_arch_mb();

	if (vq->vq_notify_host && virtqueue_notify_enabled(vq)) {
		uk_pr_debug_isr("notify queue %d\n", vq->queue_id);
		vrq->last_notified_idx = vrq->vring.avail->idx;
		vq->vq_notify_host(vq->vdev, vq->queue_id);
	}
}

static inline int virtqueue_buffer_enqueue_segments(
		struct virtqueue_vring *vrq,
		__u16 head, struct uk_sglist *sg, __u16 read_bufs,
		__u16 write_bufs)
{
	int i = 0, total_desc = 0;
	struct uk_sglist_seg *segs;
	__u16 idx = 0;

	total_desc = read_bufs + write_bufs;

	for (i = 0, idx = head; i < total_desc; i++) {
		segs = &sg->sg_segs[i];
		vrq->vring.desc[idx].addr = segs->ss_paddr;
		vrq->vring.desc[idx].len = segs->ss_len;
		vrq->vring.desc[idx].flags = 0;
		if (i >= read_bufs)
			vrq->vring.desc[idx].flags |= VRING_DESC_F_WRITE;

		if (i < total_desc - 1)
			vrq->vring.desc[idx].flags |= VRING_DESC_F_NEXT;
		idx = vrq->vring.desc[idx].next;
	}
	return idx;
}

int virtqueue_hasdata(struct virtqueue *vq)
{
	struct virtqueue_vring *vring;

	UK_ASSERT(vq);

	vring = to_virtqueue_vring(vq);
	return (vring->last_used_desc_idx != vring->vring.used->idx);
}

__u64 virtqueue_feature_negotiate(__u64 feature_set)
{
	__u64 feature = (1ULL << VIRTIO_TRANSPORT_F_START) - 1;

	/* Allow version 1 flag */
	feature |= 1ULL << VIRTIO_F_VERSION_1;
	/* Allow event index feature */
	feature |= 1ULL << VIRTIO_F_EVENT_IDX;

	feature &= feature_set;
	return feature;
}

int virtqueue_ring_interrupt(void *obj)
{
	struct virtqueue *vq = (struct virtqueue *)obj;

	UK_ASSERT(vq);

	/* It is possible that the vqueue is empty if the
	 * interrupt arrives before the data is observable
	 * by the device. In that case there's not much we
	 * can do now but defer handling to the next irq.
	 */
	if (!virtqueue_hasdata(vq))
		return 1;

	return (likely(vq->vq_callback)) ? vq->vq_callback(vq, vq->priv) : 1;
}

__paddr_t virtqueue_physaddr(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq = NULL;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool)
		return ukplat_shmem_gpa(vrq->vring.desc);
#endif
	return uk_paging_virt_to_phys((__vaddr_t)vrq->vring_mem);
}

__paddr_t virtqueue_get_avail_addr(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq = NULL;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool)
		return ukplat_shmem_gpa(vrq->vring.avail);
#endif
	return virtqueue_physaddr(vq) +
		((char *)vrq->vring.avail - (char *)vrq->vring.desc);
}

__paddr_t virtqueue_get_used_addr(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq = NULL;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool)
		return ukplat_shmem_gpa(vrq->vring.used);
#endif
	return virtqueue_physaddr(vq) +
		((char *)vrq->vring.used - (char *)vrq->vring.desc);
}

unsigned int virtqueue_vring_get_num(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq = NULL;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
	return vrq->vring.num;
}

int virtqueue_buffer_dequeue(struct virtqueue *vq, void **cookie, __u32 *len)
{
	struct virtqueue_vring *vrq = NULL;
	__u16 used_idx, head_idx;
	struct vring_used_elem *elem;

	UK_ASSERT(vq);
	UK_ASSERT(cookie);
	vrq = to_virtqueue_vring(vq);

	/* No new descriptor since last dequeue operation */
	if (!virtqueue_hasdata(vq))
		return -ENOMSG;
	used_idx = vrq->last_used_desc_idx++ & (vrq->vring.num - 1);
	elem = &vrq->vring.used->ring[used_idx];
	/**
	 * We are reading from the used descriptor information updated by the
	 * host.
	 */
	uk_arch_rmb();
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool) {
		__u32 id = __atomic_load_n(&elem->id, __ATOMIC_RELAXED);
		__u32 written = __atomic_load_n(&elem->len, __ATOMIC_RELAXED);
		int rc = virtqueue_dma_complete(vrq, id, written);

		if (rc) {
			uk_pr_err_isr("Invalid shared virtqueue completion\n");
			return rc;
		}
		head_idx = id;
		if (len)
			*len = written;
	} else
#endif
	{
		head_idx = elem->id;
		if (len)
			*len = elem->len;
	}
	*cookie = vrq->vq_info[head_idx].cookie;
	virtqueue_detach_desc(vrq, head_idx);
	vrq->vq_info[head_idx].cookie = NULL;
	return (vrq->vring.num - vrq->desc_avail);
}

int virtqueue_buffer_enqueue(struct virtqueue *vq, void *cookie,
			     struct uk_sglist *sg, __u16 read_bufs,
			     __u16 write_bufs)
{
	__u32 total_desc = 0;
	__u16 head_idx = 0, idx = 0;
	struct virtqueue_vring *vrq = NULL;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
	total_desc = read_bufs + write_bufs;
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool) {
		int count;

		if (total_desc > sg->sg_nseg || total_desc > vrq->vring.num)
			return -EINVAL;
		count = virtqueue_dma_desc_count(sg, total_desc, vrq->vring.num);
		if (count < 0)
			return count;
		total_desc = count;
	}
#endif
	if (unlikely(total_desc < 1 || total_desc > vrq->vring.num)) {
		uk_pr_err_isr("%"__PRIu32" invalid number of descriptor\n",
			      total_desc);
		return -EINVAL;
	} else if (vrq->desc_avail < total_desc) {
		uk_pr_debug_isr("Available descriptor:%"__PRIu16", Requested descriptor:%"__PRIu32"\n",
				vrq->desc_avail, total_desc);
		return -ENOSPC;
	}
	/* Get the head of free descriptor */
	head_idx = vrq->head_free_desc;
	UK_ASSERT(cookie);
	/* Additional information to reconstruct the data buffer */
	vrq->vq_info[head_idx].cookie = cookie;
	vrq->vq_info[head_idx].desc_count = total_desc;

	/**
	 * We separate the descriptor management to enqueue segment(s).
	 */
#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool) {
		int rc = virtqueue_dma_enqueue(vrq, head_idx, sg,
					      read_bufs, write_bufs, total_desc);

		if (rc < 0) {
			vrq->vq_info[head_idx].cookie = NULL;
			vrq->vq_info[head_idx].desc_count = 0;
			return rc;
		}
		idx = rc;
	} else
#endif
		idx = virtqueue_buffer_enqueue_segments(vrq, head_idx, sg,
						       read_bufs, write_bufs);
	/* Metadata maintenance for the virtqueue */
	vrq->head_free_desc = idx;
	vrq->desc_avail -= total_desc;

	uk_pr_debug_isr("Old head:%d, new head:%d, total_desc:%d\n",
			head_idx, idx, total_desc);

	virtqueue_ring_update_avail(vrq, head_idx);
	return vrq->desc_avail;
}

static void virtqueue_vring_init(struct virtqueue_vring *vrq, __u16 nr_desc,
				 __u16 align)
{
	int i = 0;

	vring_init(&vrq->vring, nr_desc, vrq->vring_mem, align);

	vrq->desc_avail = vrq->vring.num;
	vrq->head_free_desc = 0;
	vrq->last_used_desc_idx = 0;
#if CONFIG_LIBVIRTIO_SNP_DMA
	vrq->private_avail_idx = 0;
	for (i = 0; i < nr_desc; i++) {
		vrq->vq_info[i].cookie = NULL;
		vrq->vq_info[i].desc_count = 0;
		vrq->vq_info[i].next = i + 1;
	}
#endif
	for (i = 0; i < nr_desc - 1; i++)
		vrq->vring.desc[i].next = i + 1;
	/**
	 * When we reach this descriptor we have completely used all the
	 * descriptor in the vring.
	 */
	vrq->vring.desc[nr_desc - 1].next = VIRTQUEUE_MAX_SIZE;
}

struct virtqueue *virtqueue_create(__u16 queue_id, __u16 nr_descs, __u16 align,
				   virtqueue_callback_t callback,
				   virtqueue_notify_host_t notify,
				   struct virtio_dev *vdev, struct uk_alloc *a)
{
	struct virtqueue_vring *vrq;
	struct virtqueue *vq;
	int rc;
	__sz ring_size = 0;

	UK_ASSERT(a);

	vrq = uk_malloc(a, sizeof(*vrq) +
			nr_descs * sizeof(struct virtqueue_desc_info));
	if (!vrq) {
		uk_pr_err_isr("Allocation of virtqueue failed\n");
		rc = -ENOMEM;
		goto err_exit;
	}
	/**
	 * Initialize the value before referencing it in
	 * uk_posix_memalign as we don't set NULL on all failures in the
	 * allocation.
	 */
	vrq->vring_mem = NULL;
#if CONFIG_LIBVIRTIO_SNP_DMA
	vrq->dma_pool = NULL;
#endif

	ring_size = vring_size(nr_descs, align);
#if CONFIG_LIBVIRTIO_SNP_DMA
	rc = ukplat_shmem_init();
	if (rc)
		goto err_freevq;
	if (ukplat_shmem_required()) {
		/* Each descriptor array fits one page; avail/used have own GPAs. */
		if (nr_descs > 256) {
			rc = -EINVAL;
			goto err_freevq;
		}
		vrq->vring_mem = ukplat_shmem_alloc(
			ring_size, UK_PAGING_PAGE_ATTR_PROT_RW);
		if (!vrq->vring_mem) {
			rc = -ENOMEM;
			goto err_freevq;
		}
		vrq->dma_pool = ukplat_shmem_alloc(
			(__sz)nr_descs * __PAGE_SIZE, UK_PAGING_PAGE_ATTR_PROT_RW);
		if (!vrq->dma_pool) {
			ukplat_shmem_free(vrq->vring_mem);
			rc = -ENOMEM;
			goto err_freevq;
		}
		goto ring_ready;
	}
#endif
#if CONFIG_LIBUKVMEM
	struct uk_pagetable *pt = uk_paging_pt_get_active();
	__paddr_t paddr = UK_PAGING_PADDR_ANY;
	__vaddr_t vaddr = UK_PAGING_VADDR_ANY;

	ring_size = UK_PAGING_PAGE_ALIGN_UP(ring_size);

	rc = pt->fa->falloc(pt->fa, &paddr,
			    ring_size >> UK_PAGING_PAGE_SHIFT, 0);
	if (unlikely(rc))
		goto err_freevq;

	rc = uk_vma_map_dma(uk_vas_get_active(), &vaddr, ring_size,
			    UK_PAGING_PAGE_ATTR_PROT_RW, UK_VMA_MAP_POPULATE,
			    "virtqueue", paddr);
	if (unlikely(rc))
		goto err_freevq;

	vrq->vring_mem = (void *)vaddr;
#else /* !CONFIG_LIBUKVMEM */
	if (uk_posix_memalign(a, &vrq->vring_mem,
			      __PAGE_SIZE, ring_size) != 0) {
		rc = -ENOMEM;
		goto err_freevq;
	}
#endif /* !CONFIG_LIBUKVMEM */
#if CONFIG_LIBVIRTIO_SNP_DMA
ring_ready:
#endif
	memset(vrq->vring_mem, 0, ring_size);
	virtqueue_vring_init(vrq, nr_descs, align);
	vrq->uses_event_idx =
		VIRTIO_FEATURE_HAS(vdev->features, VIRTIO_F_EVENT_IDX);
	vrq->last_notified_idx = 0;


	vq = &vrq->vq;
	vq->queue_id = queue_id;
	vq->vdev = vdev;
	vq->vq_callback = callback;
	vq->vq_notify_host = notify;
	return vq;

err_freevq:
	uk_pr_err_isr("Allocation of vring failed\n");
	uk_free(a, vrq);
err_exit:
	return ERR2PTR(rc);
}

void virtqueue_destroy(__u16 align __maybe_unused,
		       struct virtqueue *vq, struct uk_alloc *a)
{
	__sz ring_size __maybe_unused;
	struct virtqueue_vring *vrq;
	int rc __maybe_unused;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);

#if CONFIG_LIBVIRTIO_SNP_DMA
	if (vrq->dma_pool) {
		if (vrq->desc_avail == vrq->vring.num) {
			ukplat_shmem_free(vrq->dma_pool);
			ukplat_shmem_free(vrq->vring_mem);
		} else {
			uk_pr_err("Retaining DMA pages with outstanding descriptors\n");
		}
		uk_free(a, vrq);
		return;
	}
#endif

	/* Free the ring */
#if CONFIG_LIBUKVMEM
	ring_size = UK_PAGING_PAGE_ALIGN_UP(vring_size(vrq->vring.num, align));
	rc = uk_vma_unmap(uk_vas_get_active(), (__vaddr_t)vrq->vring_mem,
			  ring_size, 0);
	if (unlikely(rc < 0))
		uk_pr_err("Failed to unmap virtio ring %p: %d\n",
			  vrq->vring_mem, rc);
#else /* !CONFIG_LIBUKVMEM */
	uk_free(a, vrq->vring_mem);
#endif /* !CONFIG_LIBUKVMEM */

	/* Free the virtqueue metadata */
	uk_free(a, vrq);
}

int virtqueue_is_full(struct virtqueue *vq)
{
	struct virtqueue_vring *vrq;

	UK_ASSERT(vq);

	vrq = to_virtqueue_vring(vq);
	return (vrq->desc_avail == 0);
}
