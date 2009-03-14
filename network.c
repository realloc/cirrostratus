#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <atomic_ops.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

/**********************************************************************
 * Global variables
 */

/* List of all interfaces we currently listen on */
GPtrArray *ifaces;

static void net_io(uint32_t events, void *data);

/**********************************************************************
 * Functions
 */

static void free_iface(struct netif *iface)
{
	GList *l;

	while ((l = g_queue_pop_head_link(&iface->deferred)))
		drop_request(l->data);

	if (iface->fd >= 0)
	{
		if (iface->ringptr)
		{
			struct tpacket_req req;

			munmap(iface->ringptr, iface->ringlen);
			memset(&req, 0, sizeof(req));
			setsockopt(iface->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
			g_free(iface->ring);
		}

		del_fd(iface->fd);
		close(iface->fd);
	}
	if (iface->devices->len)
		netlog(iface, LOG_ERR, "Being destroyed but devices are still attached");
	g_ptr_array_free(iface->devices, TRUE);
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
	iface->devices = g_ptr_array_new();

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

	iface->stats.rx_bytes += len;
	++iface->stats.rx_cnt;

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

#ifdef HAVE_DECL_PACKET_VERSION

/* Receive packets from the network using a ringbuffer shared with the kernel */
static void netio_ring(struct netif *iface)
{
	unsigned cnt, was_drop;
	struct tpacket2_hdr *h;
	struct timespec tv;
	void *data;

	was_drop = 0;
	for (cnt = 0; cnt < iface->ringcnt; ++cnt)
	{
		data = h = iface->ring[iface->ringidx];
		if (!h->tp_status)
			break;

		if (++iface->ringidx >= iface->ringcnt)
			iface->ringidx = 0;

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
		process_packet(iface, data + h->tp_mac, h->tp_snaplen, &tv); /* XXX h->tp_len? */
		was_drop |= h->tp_status & TP_STATUS_LOSING;

next:
		h->tp_status = 0;
		AO_nop_full();
	}
	if (cnt >= iface->ringcnt)
		++iface->stats.buffers_full;

	if (was_drop)
	{
		struct tpacket_stats stats;
		socklen_t len;

		len = sizeof(stats);
		if (!getsockopt(iface->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len))
		{
			iface->stats.dropped += stats.tp_drops;
			netlog(iface, LOG_DEBUG, "The ring missed %d packets", stats.tp_drops);
		}
	}

	iface->stats.processed += cnt;
	++iface->stats.runs;
}

/* Allocate and map the shared ring buffer */
static void setup_ring(struct netif *iface, int mtu)
{
	struct tpacket_req req;
	const char *unit;
	socklen_t len;
	unsigned i, j;
	int ret, val;

	/* The function can be called on MTU change, so destroy the previous ring
	 * if any */
	if (iface->ringptr)
	{
		munmap(iface->ringptr, iface->ringlen);
		memset(&req, 0, sizeof(req));
		setsockopt(iface->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
		iface->ringptr = NULL;
		iface->ringlen = 0;
		g_free(iface->ring);
	}

	/* We want version 2 ring buffers to avoid 64-bit uncleanness */
	val = TPACKET_V2;
	ret = setsockopt(iface->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
	if (ret)
	{
		neterr(iface, "Failed to set version 2 ring buffer format");
		return;
	}

	len = sizeof(iface->tp_hdrlen);
	ret = getsockopt(iface->fd, SOL_PACKET, PACKET_HDRLEN, &iface->tp_hdrlen, &len);
	if (ret)
	{
		neterr(iface, "Failed to determine the header length of the ring buffer");
		return;
	}

	/* Use 64k blocks so we can stuff the max. amount of jumbo frames into
	 * them with the min. amount of memory loss, and they are not yet
	 * unreasonably large */
	req.tp_block_size = 65536;
	req.tp_block_nr = iface->cfg.buffers;
	iface->frame_size = req.tp_frame_size =
		TPACKET_ALIGN(mtu + TPACKET_ALIGN(iface->tp_hdrlen + sizeof(struct sockaddr_ll)));
	req.tp_frame_nr = (req.tp_block_size / req.tp_frame_size) * req.tp_block_nr;

	ret = setsockopt(iface->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if (ret)
	{
		neterr(iface, "Failed to set up the ring buffer");
		return;
	}

	iface->ringlen = req.tp_block_size * req.tp_block_nr;
	iface->ringptr = mmap(NULL, iface->ringlen, PROT_READ | PROT_WRITE,
		MAP_SHARED, iface->fd, 0);
	if (iface->ringptr == MAP_FAILED)
	{
		neterr(iface, "Failed to mmap the ring buffer");
		memset(&req, 0, sizeof(req));
		setsockopt(iface->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
		iface->ringptr = NULL;
		iface->ringlen = 0;
		return;
	}

	iface->ring = g_new0(void *, req.tp_frame_nr);

	/* Set up pointers to the individual frames */
	for (i = iface->ringcnt = 0; i < req.tp_block_nr; i++)
		for (j = 0; j < req.tp_block_size / req.tp_frame_size; j++)
			iface->ring[iface->ringcnt++] = iface->ringptr +
				i * req.tp_block_size + j * req.tp_frame_size;

	i = human_format(iface->ringlen, &unit);
	netlog(iface, LOG_INFO, "Set up %u %s ring buffer", i, unit);
}

#else

static void netio_ring(struct netif *iface)
{
}

static void setup_ring(struct netif *iface, int mtu)
{
}

#endif /* HAVE_DECL_PACKET_VERSION */

/* Receive packets from the network using recvfrom() */
static void netio_recvfrom(struct netif *iface)
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

	if (cnt >= MAX_LOOP)
		++iface->stats.netio_recvfrom_max_hit;

	iface->stats.processed += cnt;
	++iface->stats.runs;

	free_packet(packet, iface->mtu);
}

/* Network I/O event handler callback */
static void net_io(uint32_t events, void *data)
{
	struct netif *iface = data;

	if (events & EPOLLOUT)
	{
		iface->congested = FALSE;
		while (iface->deferred.length)
		{
			GList *l = g_queue_pop_head_link(&iface->deferred);
			send_response(l->data);
			if (iface->congested)
				break;
		}

		if (!iface->deferred.length)
			modify_fd(iface->fd, &iface->event_ctx, EPOLLIN);
	}

	if (!(events & EPOLLIN))
		return;

	if (iface->ring)
		netio_ring(iface);
	else
		netio_recvfrom(iface);
}

void send_response(struct queue_item *q)
{
	struct netif *const iface = q->iface;
	static char zeroes[ETH_ZLEN];
	struct iovec iov[3];
	struct msghdr msg;
	unsigned len;
	int ret;

	if (!iface || iface->fd == -1)
	{
		drop_request(q);
		return;
	}

	if (iface->congested)
	{
		g_queue_push_tail_link(&iface->deferred, &q->chain);
		return;
	}

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
		g_queue_push_tail_link(&iface->deferred, &q->chain);
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

/* Validate an interface when it is found */
void validate_iface(const char *name, int ifindex, int mtu, const char *macaddr)
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

	if (iface->cfg.mtu && mtu > iface->cfg.mtu)
		mtu = iface->cfg.mtu;
	if (iface->mtu != mtu)
	{
		if (iface->mtu)
			netlog(iface, LOG_NOTICE, "MTU changed to %d", mtu);
		if (iface->ring)
			setup_ring(iface, mtu);
		iface->mtu = mtu;
	}

	memcpy(&iface->mac, macaddr, ETH_ALEN);

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
		if (iface->cfg.buffers)
			setup_ring(iface, mtu);

		memset(&sa, 0, sizeof(sa));
		sa.sll_family = AF_PACKET;
		sa.sll_protocol = htons(ETH_P_AOE);
		sa.sll_ifindex = ifindex;

		if (bind(iface->fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		{
			neterr(iface, "bind() failed");
			return invalidate_iface(ifindex);
		}

		add_fd(iface->fd, &iface->event_ctx);

		netlog(iface, LOG_INFO, "Listener started (MTU: %d)", mtu);
	}

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
