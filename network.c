#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <atomic_ops.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

/* This is _really_ nasty. "struct tpacket_hdr" is not 64-bit clean, so if you
 * are running a 32-bit userland with a 64-bit kernel, things will be misaligned.
 * So we have to check the kernel at run-time and adapt accordingly. Ugh. */
#if defined(__i486__)

#include <sys/utsname.h>

struct tpacket_hdr64
{
	uint64_t	tp_status;
	uint32_t	tp_len;
	uint32_t	tp_snaplen;
	uint16_t	tp_mac;
	uint16_t	tp_net;
	uint32_t	tp_sec;
	uint32_t	tp_usec;
};

static int broken_tp_header;

#elif defined(__x86_64__)
	/* Nothing */
#else
#warning I don't know your architecture, mmap'ed packets may be broken
#endif

/**********************************************************************
 * Global variables
 */

/* List of all interfaces we currently listen on */
static GPtrArray *ifaces;

static void net_io(uint32_t events, void *data);

/**********************************************************************
 * Functions
 */

static void free_iface(struct netif *iface)
{
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

/* Match a MAC address against an ACL */
static int match_acl(GArray *acls, const void *mac)
{
	unsigned i;

	for (i = 0; i < acls->len; i++)
		if (!memcmp(&g_array_index(acls, struct ether_addr, i), mac, ETH_ALEN))
			return TRUE;
	return FALSE;
}

/* Process a packet received from the network */
static void process_packet(struct netif *iface, void *packet, unsigned len, struct timeval *tv)
{
	struct aoe_hdr *hdr = packet;
	struct device *dev;
	int shelf, slot;
	unsigned i;

	/* Check protocol */
	if (G_UNLIKELY(hdr->addr.ether_type != htons(ETH_P_AOE)))
	{
		iface->stats.dropped++;
		return;
	}

	/* Check protocol version */
	if (G_UNLIKELY(hdr->version != AOE_VERSION))
	{
		iface->stats.dropped++;
		return;
	}

	/* Ignore responses */
	if (hdr->is_response)
	{
		iface->stats.dropped++;
		return;
	}

	iface->stats.rx_bytes += len;
	++iface->stats.rx_cnt;

	shelf = ntohs(hdr->shelf);
	slot = hdr->slot;

	for (i = 0; i < iface->devices->len; i++)
	{
		dev = g_ptr_array_index(iface->devices, i);
		if ((shelf != SHELF_BCAST || slot != SLOT_BCAST) &&
				(dev->cfg.shelf != shelf || dev->cfg.slot != slot))
			continue;

		/* Check the ACLs */
		if (dev->cfg.accept && !match_acl(dev->cfg.accept,
				&hdr->addr.ether_shost))
			continue;
		if (dev->cfg.deny && match_acl(dev->cfg.deny,
				&hdr->addr.ether_shost))
			continue;

		process_request(iface, dev, packet, len, NULL);
		if (shelf != SHELF_BCAST || slot != SLOT_BCAST)
			break;
	}

	/* We cannot really tell if a broadcast packet was processed or not... */
	if ((shelf != SHELF_BCAST || slot != SLOT_BCAST) && i >= iface->devices->len)
		iface->stats.dropped++;
}

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

/* Receive packets from the network using a ringbuffer shared with the kernel */
static void netio_ring(struct netif *iface)
{
	unsigned cnt, was_drop;
	struct tpacket_hdr *h;
	struct timeval tv;
	void *data;

	was_drop = 0;
	for (cnt = 0; cnt < iface->ringcnt; ++cnt)
	{
#if defined(__i486__)
		struct tpacket_hdr64 *h2;

		if (broken_tp_header)
		{
			data = h2 = iface->ring[iface->ringidx];
			h = alloca(sizeof(*h));

			h->tp_status = h2->tp_status;
			h->tp_len = h2->tp_len;
			h->tp_snaplen = h2->tp_snaplen;
			h->tp_mac = h2->tp_mac;
			h->tp_net = h2->tp_net;
			h->tp_sec = h2->tp_sec;
			h->tp_usec = h2->tp_usec;
		}
		else
			data = h = iface->ring[iface->ringidx];
#elif defined(__x86_64__)
		data = h = iface->ring[iface->ringidx];
#else
#warning I don't know your architecture, mmap'ed packets may be broken
#endif
		if (!h->tp_status)
			break;

		if (++iface->ringidx >= iface->ringcnt)
			iface->ringidx = 0;

		if (G_UNLIKELY(h->tp_snaplen < (int)sizeof(struct aoe_hdr)))
		{
			++iface->stats.dropped;
			goto next;
		}

		/* Use the receiving time of the packet as the start time of
		 * the request */
		tv.tv_sec = h->tp_sec;
		tv.tv_usec = h->tp_usec;

		/* The AoE header also contains the ethernet header, so we have
		 * start from h->tp_mac instead of h->tp_net */
		process_packet(iface, data + h->tp_mac, h->tp_snaplen, &tv); /* XXX h->tp_len? */
		was_drop |= h->tp_status & TP_STATUS_LOSING;

next:
#if defined(__i486__)
		if (broken_tp_header)
			h2->tp_status = 0;
		else
			h->tp_status = 0;
#elif defined(__x86_64__)
		h->tp_status = 0;
#else
#warning I don't know your architecture, mmap'ed packets may be broken
#endif
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
			iface->stats.dropped += stats.tp_drops;
	}

	iface->stats.processed += cnt;
	++iface->stats.runs;
}

/* Network I/O event handler callback */
static void net_io(uint32_t events, void *data)
{
	struct netif *iface = data;
	struct device *dev;
	unsigned i;

	if (events & EPOLLOUT)
	{
		int congested = 0;

		for (i = 0; i < iface->devices->len; i++)
		{
			dev = g_ptr_array_index(iface->devices, i);

			if (!dev->congested)
				continue;
			run_queue(dev, 0);
			congested |= dev->congested;
		}
		if (!congested)
		{
			modify_fd(iface->fd, &iface->event_ctx, EPOLLIN);
			iface->congested = FALSE;
		}
	}

	if (!(events & EPOLLIN))
		return;

	if (iface->ring)
		netio_ring(iface);
	else
		netio_recvfrom(iface);
}

/* Allocate and map the shared ring buffer */
static void setup_ring(struct netif *iface, int mtu)
{
	struct tpacket_req req;
	const char *unit;
	unsigned i, j;
	int ret;

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

	/* Use 64k blocks so we can stuff the max. amount of jumbo frames into
	 * them with the min. amount of memory loss, and they are not yet
	 * unreasonably large */
	req.tp_block_size = 65536;
	req.tp_block_nr = iface->cfg.buffers;
	/* The "+ 16" is there for the MAC address */
	iface->frame_size = req.tp_frame_size =
		TPACKET_ALIGN(mtu) + TPACKET_ALIGN(TPACKET_HDRLEN + 16);
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
			attach_devices(iface);
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

	attach_devices(iface);
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

void report_net_stats(int fd)
{
	uint32_t val, i;

	val = ifaces->len;
	write(fd, &val, sizeof(val));

	for (i = 0; i < ifaces->len; i++)
	{
		struct netif *iface = g_ptr_array_index(ifaces, i);

		val = strlen(iface->name);
		write(fd, &val, sizeof(val));
		write(fd, iface->name, strlen(iface->name));
		val = sizeof(iface->stats);
		write(fd, &val, sizeof(val));
		write(fd, &iface->stats, sizeof(iface->stats));
	}
}

void setup_ifaces(void)
{
	unsigned i;

	/* Test for broken "struct tp_header" if this is a 32-bit process
	 * running on a 64-bit kernel. This test will not work if the process
	 * was started with linux32, but if someone does that, he gets what
	 * he deserves. */
#if defined(__i486__)
	{
		struct utsname uts;

		uname(&uts);
		if (!strcmp(uts.machine, "x86_64"))
			broken_tp_header = 1;
	}
#elif defined(__x86_64__)
	/* Nothing */
#else
#warning I don't know your architecture, mmap'ed packets may be broken
#endif

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
