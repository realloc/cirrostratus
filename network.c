#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <atomic_ops.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

/* These were added in kernel 2.6.31 */
#ifndef PACKET_TX_RING
#define PACKET_TX_RING		13
#define PACKET_LOSS		14
#define TP_STATUS_AVAILABLE	0x0
#define TP_STATUS_SEND_REQUEST	0x1
#define TP_STATUS_SENDING	0x2
#define TP_STATUS_WRONG_FORMAT	0x4
#endif /* PACKET_TX_RING */

/**********************************************************************
 * Global variables
 */

/* List of all interfaces we currently listen on */
GPtrArray *ifaces;

GQueue active_ifaces;

static void net_io(uint32_t events, void *data);
static void destroy_one_ring(struct netif *iface, int what);

/**********************************************************************
 * Generic functions
 */

static void free_iface(struct netif *iface)
{
	unsigned i;

	for (i = 0; i < iface->deferred->len; i++)
		drop_request(g_ptr_array_index(iface->deferred, i));
	if (iface->deferred->len)
		g_ptr_array_remove_range(iface->deferred, 0, iface->deferred->len);

	if (iface->fd >= 0)
	{
		if (iface->ring_ptr)
		{
			munmap(iface->ring_ptr, iface->ring_len);
			destroy_one_ring(iface, PACKET_RX_RING);
			destroy_one_ring(iface, PACKET_TX_RING);
		}
		del_fd(iface->fd);
		close(iface->fd);
	}
	if (iface->devices->len)
		netlog(iface, LOG_ERR, "Being destroyed but devices are still attached");
	g_ptr_array_free(iface->devices, TRUE);
	g_ptr_array_free(iface->deferred, TRUE);
	g_free(iface->name);
	g_slice_free(struct netif, iface);
}

static struct netif *alloc_iface(int ifindex, const char *name)
{
	struct netif *iface;

	iface = g_slice_new0(struct netif);
	iface->ifindex = ifindex;
	iface->fd = -1;
	iface->name = g_strdup(name);
	iface->event_ctx.callback = net_io;
	iface->event_ctx.data = iface;
	iface->devices = g_ptr_array_new();
	iface->deferred = g_ptr_array_new();
	iface->chain.data = iface;

	if (!get_netif_config(name, &iface->cfg))
	{
		free_iface(iface);
		return NULL;
	}

	return iface;
}

/* Process a packet received from the network */
static void process_packet(struct netif *iface, void *packet, unsigned len,
	const struct timespec *tv)
{
	const struct aoe_hdr *hdr = packet;
	unsigned i, l, u, shelf, slot;
	struct device *dev;

	iface->stats.rx_bytes += len;
	++iface->stats.rx_cnt;

	/* Check protocol */
	if (G_UNLIKELY(hdr->addr.ether_type != htons(ETH_P_AOE)))
	{
		iface->stats.ignored++;
		return;
	}

	/* Check protocol version */
	if (G_UNLIKELY(hdr->version != AOE_VERSION))
	{
		iface->stats.ignored++;
		return;
	}

	/* Ignore responses */
	if (hdr->is_response)
	{
		iface->stats.ignored++;
		return;
	}

	shelf = hdr->shelf;
	slot = hdr->slot;

	/* Broadcast requests: do a linear scan */
	if (G_UNLIKELY(shelf == htons(SHELF_BCAST) || slot == SLOT_BCAST))
	{
		int processed = FALSE;

		for (i = 0; i < iface->devices->len; i++)
		{
			dev = g_ptr_array_index(iface->devices, i);
			if ((shelf == htons(SHELF_BCAST) || dev->cfg.shelf == shelf) &&
					(slot == SLOT_BCAST || dev->cfg.slot == slot))
			{
				process_request(iface, dev, packet, len, tv);
				processed = TRUE;
			}
		}
		if (processed)
			iface->stats.broadcast++;
		else
			iface->stats.ignored++;
		return;
	}

	/* Not a broadcast: do a binary search */
	l = 0;
	u = iface->devices->len;
	while (l < u)
	{
		i = (l + u) / 2;
		dev = g_ptr_array_index(iface->devices, i);

		if (dev->cfg.shelf < shelf || (dev->cfg.shelf == shelf &&
				dev->cfg.slot < slot))
			l = i + 1;
		else if (dev->cfg.shelf > shelf || (dev->cfg.shelf == shelf &&
				dev->cfg.slot > slot))
			u = i;
		else
			return process_request(iface, dev, packet, len, tv);
	}
	iface->stats.ignored++;
}

/**********************************************************************
 * Memory mapped ring buffer handling
 */

/* Receive packets from the network using a ringbuffer shared with the kernel */
static void rx_ring(struct netif *iface)
{
	unsigned cnt, was_drop;
	struct tpacket2_hdr *h;
	struct timespec tv;
	void *data;

	was_drop = 0;
	for (cnt = 0; cnt < iface->rx_ring.cnt; ++cnt)
	{
		data = h = iface->rx_ring.frames[iface->rx_ring.idx];
		if (!h->tp_status)
			break;

		if (++iface->rx_ring.idx >= iface->rx_ring.cnt)
			iface->rx_ring.idx = 0;

		if (G_UNLIKELY(h->tp_snaplen < (int)sizeof(struct aoe_hdr)))
		{
			netlog(iface, LOG_DEBUG, "Packet too short");
			++iface->stats.dropped;
			goto next;
		}

		/* Use the receiving time of the packet as the start time of
		 * the request */
		tv.tv_sec = h->tp_sec;
		tv.tv_nsec = h->tp_nsec;

		/* The AoE header also contains the ethernet header, so we have
		 * start from h->tp_mac instead of h->tp_net */
		process_packet(iface, data + h->tp_mac, h->tp_snaplen, &tv);
		was_drop |= h->tp_status & TP_STATUS_LOSING;

next:
		h->tp_status = TP_STATUS_KERNEL;
		/* Make sure other CPUs know about the status change */
		AO_nop_full();
	}
	if (cnt >= iface->rx_ring.cnt)
		++iface->stats.rx_buffers_full;

	if (was_drop)
	{
		struct tpacket_stats stats;
		socklen_t len;

		len = sizeof(stats);
		if (!getsockopt(iface->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len))
			iface->stats.dropped += stats.tp_drops;
	}

	++iface->stats.rx_runs;
}

static void tx_ring(struct netif *iface, struct queue_item *q)
{
	struct tpacket2_hdr *h;
	unsigned cnt;
	void *data;

	/* This may happen if the MTU changes while requests are
	 * in flight */
	if (G_UNLIKELY(q->hdrlen + q->length > (unsigned)iface->mtu))
	{
		drop_request(q);
		return;
	}

	for (cnt = 0; cnt < iface->tx_ring.cnt; ++cnt)
	{
		h = iface->tx_ring.frames[iface->tx_ring.idx++];
		if (iface->tx_ring.idx >= iface->tx_ring.cnt)
			iface->tx_ring.idx = 0;
		if (h->tp_status == TP_STATUS_AVAILABLE ||
				h->tp_status == TP_STATUS_WRONG_FORMAT)
			break;

	}
	if (cnt >= iface->tx_ring.cnt)
	{
		++iface->stats.tx_buffers_full;
		g_ptr_array_add(iface->deferred, q);
		if (!iface->congested)
		{
			modify_fd(iface->fd, &iface->event_ctx, EPOLLIN | EPOLLOUT);
			iface->congested = TRUE;
		}
		return;
	}

	/* Should not happen */
	if (G_UNLIKELY(h->tp_status == TP_STATUS_WRONG_FORMAT))
		netlog(iface, LOG_ERR, "Bad packet format on send");

	/* Fill the frame */
	data = (void *)h + iface->tp_hdrlen;
	memcpy(data, &q->aoe_hdr, q->hdrlen);
	h->tp_len = q->hdrlen;
	if (q->length)
	{
		memcpy(data + q->hdrlen, q->buf, q->length);
		h->tp_len += q->length;
	}

	iface->stats.tx_bytes += h->tp_len;
	++iface->stats.tx_cnt;
	if (q->dev && G_UNLIKELY(q->dev->cfg.trace_io))
		devlog(q->dev, LOG_DEBUG, "%s/%08x: Response sent",
			ether_ntoa((struct ether_addr *)&q->aoe_hdr.addr.ether_dhost),
			(uint32_t)ntohl(q->aoe_hdr.tag));

	drop_request(q);

	/* Make sure buffer writes are stable before we update the status */
	AO_nop_write();
	h->tp_status = TP_STATUS_SEND_REQUEST;
	/* Make sure other CPUs know about the status change */
	AO_nop_full();

	if (!iface->is_active)
	{
		g_queue_push_tail_link(&active_ifaces, &iface->chain);
		iface->is_active = TRUE;
	}
}

/* Call send() for interfaces that have packets queued in the ring buffer */
void run_ifaces(void)
{
	GList *l;
	int ret;

	while ((l = g_queue_pop_head_link(&active_ifaces)))
	{
		struct netif *iface = l->data;

		iface->is_active = FALSE;
		ret = send(iface->fd, NULL, 0, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (ret == -1 && errno != EAGAIN)
			neterr(iface, "Async write error");
		else
			++iface->stats.tx_runs;
	}
}

static void setup_one_ring(struct netif *iface, unsigned ring_size, int mtu, int what)
{
	unsigned page_size, max_blocks;
	struct tpacket_req req;
	struct ring *ring;
	const char *name;
	int ret;

	name = what == PACKET_RX_RING ? "RX" : "TX";
	ring = what == PACKET_RX_RING ? &iface->rx_ring : &iface->tx_ring;

	/* For RX, the frame looks like:
	 * - struct tpacket2_hdr
	 * - padding to 16-byte boundary (this is included in iface->tp_hdrlen)
	 * - padding: 16 - sizeof(struct ether_hdr)
	 * - raw packet
	 * - padding to 16-byte boundary
	 *
	 * So the raw packet is aligned so that the data part starts on a
	 * 16-byte boundary, not the packet header. This means we need an extra
	 * 16 bytes for the frame size.
	 *
	 * The TX frame is simpler:
	 * - struct tpacket2_hdr
	 * - padding to 16-byte boundary (this is included in iface->tp_hdrlen)
	 * - raw packet
	 * - padding to 16-byte boundary */
	ring->frame_size = req.tp_frame_size = TPACKET_ALIGN(iface->tp_hdrlen + 16 + mtu);

	/* The number of blocks is limited by the kernel implementation */
	page_size = sysconf(_SC_PAGESIZE);
	max_blocks = page_size / sizeof(void *);

	/* Start with a large block size and if that fails try to lower it */
	req.tp_block_size = 64 * 1024;

	ret = -1;
	while (req.tp_block_size > req.tp_frame_size && req.tp_block_size >= page_size)
	{
		req.tp_block_nr = ring_size / req.tp_block_size;
		if (req.tp_block_nr > max_blocks)
			req.tp_block_nr = max_blocks;

		req.tp_frame_nr = (req.tp_block_size / req.tp_frame_size) * req.tp_block_nr;

		ret = setsockopt(iface->fd, SOL_PACKET, what, &req, sizeof(req));
		if (!ret)
			break;
		req.tp_block_size >>= 1;
	}
	if (ret)
	{
		neterr(iface, "Failed to set up the %s ring buffer", name);
		memset(ring, 0, sizeof(*ring));
		return;
	}

	ring->len = req.tp_block_size * req.tp_block_nr;
	ring->block_size = req.tp_block_size;
	ring->cnt = req.tp_frame_nr;
	ring->frames = g_new0(void *, req.tp_frame_nr);
}

static void destroy_one_ring(struct netif *iface, int what)
{
	struct tpacket_req req;
	struct ring *ring;

	ring = what == PACKET_RX_RING ? &iface->rx_ring : &iface->tx_ring;

	memset(&req, 0, sizeof(req));
	setsockopt(iface->fd, SOL_PACKET, what, &req, sizeof(req));
	g_free(ring->frames);
	memset(ring, 0, sizeof(*ring));
}

/* Set up pointers to the individual frames */
static void setup_frames(struct ring *ring, void *data)
{
	unsigned i, j, cnt, blocks, frames;

	/* Number of blocks in the ring */
	blocks = ring->len / ring->block_size;
	/* Number of frames in a block */
	frames = ring->block_size / ring->frame_size;

	for (i = cnt = 0; i < blocks; i++)
		for (j = 0; j < frames; j++)
			ring->frames[cnt++] = data + i * ring->block_size + j * ring->frame_size;
}

/* Allocate and map the shared ring buffer */
static void setup_rings(struct netif *iface, unsigned size, int mtu)
{
	const char *unit;
	socklen_t len;
	int ret, val;

	/* The function can be called on MTU change, so destroy the previous ring
	 * if any */
	if (iface->ring_ptr)
	{
		munmap(iface->ring_ptr, iface->ring_len);
		iface->ring_ptr = NULL;
		iface->ring_len = 0;
		destroy_one_ring(iface, PACKET_RX_RING);
		destroy_one_ring(iface, PACKET_TX_RING);
	}

	if (!size)
		return;

	/* We want version 2 ring buffers to avoid 64-bit uncleanness */
	val = TPACKET_V2;
	ret = setsockopt(iface->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
	if (ret)
	{
		neterr(iface, "Failed to set version 2 ring buffer format");
		return;
	}

	val = TPACKET_V2;
	len = sizeof(val);
	ret = getsockopt(iface->fd, SOL_PACKET, PACKET_HDRLEN, &val, &len);
	if (ret)
	{
		neterr(iface, "Failed to determine the header length of the ring buffer");
		return;
	}
	iface->tp_hdrlen = TPACKET_ALIGN(val);

	/* Drop badly formatted packets */
	val = 1;
	ret = setsockopt(iface->fd, SOL_PACKET, PACKET_LOSS, &val, sizeof(val));
	if (ret)
		neterr(iface, "Failed to set packet drop mode");

	/* The RX and TX rings share the memory mapped area, so give
	 * half the requested size to each */
	setup_one_ring(iface, size * 1024 / 2, mtu, PACKET_RX_RING);
	setup_one_ring(iface, size * 1024 / 2, mtu, PACKET_TX_RING);

	/* Both rings must be mapped using a single mmap() call */
	iface->ring_len = iface->rx_ring.len + iface->tx_ring.len;
	if (!iface->ring_len)
		return;
	iface->ring_ptr = mmap(NULL, iface->ring_len, PROT_READ | PROT_WRITE,
		MAP_SHARED, iface->fd, 0);
	if (iface->ring_ptr == MAP_FAILED)
	{
		neterr(iface, "Failed to mmap the ring buffer");
		destroy_one_ring(iface, PACKET_RX_RING);
		destroy_one_ring(iface, PACKET_TX_RING);
		iface->ring_ptr = NULL;
		iface->ring_len = 0;
		return;
	}

	len = 0;
	if (iface->rx_ring.len)
	{
		setup_frames(&iface->rx_ring, iface->ring_ptr);
		len = iface->rx_ring.len;
	}
	if (iface->tx_ring.len)
		setup_frames(&iface->tx_ring, iface->ring_ptr + len);

	len = human_format(iface->ring_len, &unit);
	netlog(iface, LOG_INFO, "Set up %u %s ring buffer (%u RX/%u TX packets)",
		len, unit, iface->rx_ring.cnt, iface->tx_ring.cnt);
}

/**********************************************************************
 * Traditional single-packet I/O
 */

/* Receive packets from the network using recvfrom() */
static void rx_recvfrom(struct netif *iface)
{
	unsigned cnt;
	void *packet;
	int len;

	packet = alloc_packet(iface->mtu);

	/* Limit the number of requests to process before giving back
	 * control to other tasks */
#define MAX_LOOP 64
	for (cnt = 0; cnt < MAX_LOOP; cnt++)
	{
		len = recvfrom(iface->fd, packet, iface->mtu,
			MSG_DONTWAIT | MSG_TRUNC, NULL, NULL);
		if (len < 0)
		{
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			neterr(iface, "Read error");
			del_fd(iface->fd);
			close(iface->fd);
			iface->fd = -1;
			break;
		}

		if (G_UNLIKELY(len < (int)sizeof(struct aoe_hdr)))
		{
			netlog(iface, LOG_DEBUG, "Packet too short");
			iface->stats.dropped++;
			continue;
		}
		if (G_UNLIKELY(len > iface->mtu))
		{
			netlog(iface, LOG_ERR, "Received packet size (%d) is larger than "
				"the configured MTU", len);
			iface->stats.dropped++;
			continue;
		}
		process_packet(iface, packet, len, NULL);
	}

	++iface->stats.rx_runs;

	free_packet(packet, iface->mtu);
}

static void tx_sendmsg(struct netif *iface, struct queue_item *q)
{
	static char zeroes[ETH_ZLEN];
	struct iovec iov[3];
	struct msghdr msg;
	unsigned len;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;

	iov[0].iov_base = &q->aoe_hdr;
	iov[0].iov_len = len = q->hdrlen;
	msg.msg_iovlen++;

	if (q->length)
	{
		iov[msg.msg_iovlen].iov_base = q->buf;
		iov[msg.msg_iovlen++].iov_len = q->length;
		len += q->length;
	}

	/* If the frame is too small then it must be padded. On real networks
	 * this is not neccessary but virtual interfaces tend to "forget" the
	 * padding and that can make clients unhappy */
	if (len < ETH_ZLEN)
	{
		iov[msg.msg_iovlen].iov_base = zeroes;
		iov[msg.msg_iovlen++].iov_len = ETH_ZLEN - len;
	}

	ret = sendmsg(iface->fd, &msg, MSG_DONTWAIT);
	if (ret != -1)
	{
		iface->stats.tx_bytes += ret;
		++iface->stats.tx_cnt;
		if (q->dev && G_UNLIKELY(q->dev->cfg.trace_io))
			devlog(q->dev, LOG_DEBUG, "%s/%08x: Response sent",
				ether_ntoa((struct ether_addr *)&q->aoe_hdr.addr.ether_dhost),
				(uint32_t)ntohl(q->aoe_hdr.tag));
		drop_request(q);
		return;
	}

	if (errno == EAGAIN)
	{
		++iface->stats.tx_buffers_full;
		g_ptr_array_add(iface->deferred, q);
		if (!iface->congested)
		{
			modify_fd(iface->fd, &iface->event_ctx, EPOLLIN | EPOLLOUT);
			iface->congested = TRUE;
		}
	}
	else
	{
		neterr(iface, "Write error");
		drop_request(q);
	}
}

/**********************************************************************
 * Generic I/O handling
 */

/* Network I/O event handler callback */
static void net_io(uint32_t events, void *data)
{
	struct netif *iface = data;
	unsigned i;

	if (events & EPOLLOUT)
	{
		iface->congested = FALSE;
		for (i = 0; i < iface->deferred->len; i++)
		{
			struct queue_item *q;

			q = g_ptr_array_index(iface->deferred, i);
			send_response(q);
			if (iface->congested)
			{
				/* send_response() adds the request to
				 * the end of the deferred queue when it
				 * sets the congested flag, so we must
				 * remove the duplicate entry here */
				++i;
				break;
			}
		}
		g_ptr_array_remove_range(iface->deferred, 0, i);

		if (!iface->deferred->len)
			modify_fd(iface->fd, &iface->event_ctx, EPOLLIN);
	}

	if (events & EPOLLIN)
	{
		if (iface->rx_ring.frames)
			rx_ring(iface);
		else
			rx_recvfrom(iface);
	}
}

void send_response(struct queue_item *q)
{
	struct netif *const iface = q->iface;

	if (!iface || iface->fd == -1)
	{
		drop_request(q);
		return;
	}

	if (iface->congested)
	{
		g_ptr_array_add(iface->deferred, q);
		return;
	}

	if (iface->tx_ring.frames)
		tx_ring(iface, q);
	else
		tx_sendmsg(iface, q);
}

static int dev_sort(const void *a, const void *b)
{
	const struct device *const *deva = a;
	const struct device *const *devb = b;

	/* Note: dev->cfg.shelf is in network byte order so the following
	 * will not give a natural order */
	if ((*deva)->cfg.shelf == (*devb)->cfg.shelf)
		return (*deva)->cfg.slot - (*devb)->cfg.slot;
	else
		return (*deva)->cfg.shelf - (*devb)->cfg.shelf;
}

/* Attach any new devices to the interface and ensure that the list
 * is sorted by shelf/slot */
static void attach_new_devices(struct netif *iface)
{
	g_ptr_array_foreach(devices, attach_device, iface);
	g_ptr_array_sort(iface->devices, dev_sort);
}

static void setup_filter(struct netif *iface)
{
	static struct sock_filter filter[] =
	{
		/* Load the type into register */
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
		/* Does it match AoE (0x88a2)? */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x88a2, 0, 4),
		/* Load the flags into register */
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 14),
		/* Check to see if the Resp flag is set */
		BPF_STMT(BPF_ALU+BPF_AND+BPF_K, (1 << 3)),
		/* Yes, goto INVALID */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1),
		/* VALID: return -1 (allow the packet to be read) */
		BPF_STMT(BPF_RET+BPF_K, -1),
		/* INVALID: return 0 (ignore the packet) */
		BPF_STMT(BPF_RET+BPF_K, 0),
	};
	static struct sock_fprog prog =
	{
		.filter = filter,
		.len = G_N_ELEMENTS(filter)
	};

	if (setsockopt(iface->fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)))
		neterr(iface, "Failed to set up the socket filter");
}

/* Setting SO_SNDBUF/SO_RCVBUF is just advisory, so report the real value being
 * used */
static void set_buffer(struct netif *iface, int what, int size)
{
	const char *unit;
	socklen_t len;
	int ret, val;

	ret = setsockopt(iface->fd, SOL_SOCKET, what, &size, sizeof(size));
	if (ret)
	{
		neterr(iface, "Failed to set the %s buffer size",
			what == SO_SNDBUF ? "send" : "receive");
		return;
	}

	len = sizeof(val);
	if (getsockopt(iface->fd, SOL_SOCKET, what, &val, &len))
		val = size;
	ret = human_format(val, &unit);
	netlog(iface, LOG_INFO, "The %s buffer is %d %s",
		what == SO_SNDBUF ? "send" : "receive", ret, unit);
}

/* Validate an interface when it is found */
void validate_iface(const char *name, int ifindex, int mtu, const char *macaddr)
{
	struct netif_config newcfg;
	struct netif *iface;
	unsigned i;

	for (i = 0; i < ifaces->len; i++)
	{
		iface = g_ptr_array_index(ifaces, i);
		if (iface->ifindex == ifindex)
			break;
	}

	if (i >= ifaces->len)
	{
		/* This is a new interface. Check if we want to listen on this
		 * interface or not */
		if (!match_patternlist(defaults.interfaces, name))
			return logit(LOG_DEBUG, "net/%s: Does not match the configured "
				"pattern list, ignoring", name);

		iface = alloc_iface(ifindex, name);
		g_ptr_array_add(ifaces, iface);
	}
	else
	{
		/* The interface already exists. If we no longer want to listen on
		 * this interface, invalidate it */
		if (!match_patternlist(defaults.interfaces, name))
			return invalidate_iface(ifindex);

		/* If the interface got renamed, re-validate the list of attached
		 * devices */
		if (strcmp(iface->name, name))
		{
			netlog(iface, LOG_NOTICE, "Interface name changed to %s",
				name);
			g_free(iface->name);
			iface->name = g_strdup(name);

			while (iface->devices->len)
				detach_device(iface, g_ptr_array_index(iface->devices, 0));

			attach_new_devices(iface);
		}
	}

	memcpy(&iface->mac, macaddr, ETH_ALEN);

	/* If the new configuration has errors, just use the old config */
	if (!get_netif_config(iface->name, &newcfg))
		newcfg = iface->cfg;

	/* Clamp the MTU if the configuration says so */
	if (newcfg.mtu && mtu > newcfg.mtu)
		mtu = newcfg.mtu;

	if (iface->fd == -1)
	{
		struct sockaddr_ll sa;

		iface->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_AOE));
		if (iface->fd == -1)
		{
			neterr(iface, "Failed to allocate network socket");
			return invalidate_iface(ifindex);
		}

		/* Set up the ring buffer before binding the socket to avoid
		 * packets ending up in the normal receive buffer */
		setup_rings(iface, newcfg.ring_size, mtu);
		iface->mtu = mtu;

		memset(&sa, 0, sizeof(sa));
		sa.sll_family = AF_PACKET;
		sa.sll_protocol = htons(ETH_P_AOE);
		sa.sll_ifindex = ifindex;

		if (bind(iface->fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		{
			neterr(iface, "bind() failed");
			return invalidate_iface(ifindex);
		}

		setup_filter(iface);
		add_fd(iface->fd, &iface->event_ctx);

		netlog(iface, LOG_INFO, "Listener started (MTU: %d)", mtu);

		/* We _are_ using the OS default at this point */
		iface->cfg.send_buf_size = 0;
		iface->cfg.recv_buf_size = 0;
	}
	else
	{
		/* If either the MTU or the ring buffer size changes, we have
		 * to destroy & re-allocate the ring buffer */
		if (iface->mtu != mtu || newcfg.ring_size != iface->cfg.ring_size)
			setup_rings(iface, newcfg.ring_size, mtu);

		/* If the MTU has changed, tell it to the initiators */
		if (iface->mtu != mtu)
		{
			netlog(iface, LOG_NOTICE, "MTU changed to %d", mtu);
			iface->mtu = mtu;

			for (i = 0; i < iface->devices->len; i++)
				send_advertisment(g_ptr_array_index(iface->devices, i), iface);
		}
	}


	if (newcfg.send_buf_size &&
			newcfg.send_buf_size != iface->cfg.send_buf_size)
		set_buffer(iface, SO_SNDBUF, newcfg.send_buf_size * 1024);

	if (newcfg.recv_buf_size &&
			newcfg.recv_buf_size != iface->cfg.recv_buf_size)
		set_buffer(iface, SO_RCVBUF, newcfg.recv_buf_size * 1024);

	/* destroy_netif_config(&iface->cfg); */
	iface->cfg = newcfg;

	attach_new_devices(iface);
}

void invalidate_iface(int ifindex)
{
	struct netif *iface;
	unsigned i;

	for (i = 0; i < ifaces->len; i++)
	{
		iface = g_ptr_array_index(ifaces, i);
		if (iface->ifindex == ifindex)
			break;
	}
	if (i >= ifaces->len)
		return;

	netlog(iface, LOG_DEBUG, "Shutting down");

	/* Keep the interface order, it is important for re-validation */
	g_ptr_array_remove_index(ifaces, i);

	while (iface->devices->len)
		detach_device(iface, g_ptr_array_index(iface->devices, 0));

	free_iface(iface);
}

void setup_ifaces(void)
{
	unsigned i;

	if (!ifaces)
		ifaces = g_ptr_array_new();

	/* Re-validate all interfaces */
	for (i = 0; i < ifaces->len;)
	{
		struct netif *iface = g_ptr_array_index(ifaces, i);

		if (!match_patternlist(defaults.interfaces, iface->name))
			invalidate_iface(iface->ifindex);
		else
			i++;
	}

	/* Trigger a device enumeration in case the new configuration enabled
	 * more interfaces */
	netmon_enumerate();
}

void done_ifaces(void)
{
	struct netif *iface;

	while (ifaces->len)
	{
		iface = g_ptr_array_index(ifaces, 0);
		invalidate_iface(iface->ifindex);
	}
	g_ptr_array_free(ifaces, TRUE);
}
