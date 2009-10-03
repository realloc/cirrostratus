#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <sys/types.h>
#include <netinet/ether.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <libaio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

/**********************************************************************
 * Definitions
 */

/* Number of I/O events to submit/receive in one system call */
#define EVENT_BATCH		32

/**********************************************************************
 * Forward declarations
 */

static void dev_io(uint32_t events, void *data);
static void dev_timer(uint32_t events, void *data);
static void run_queue(struct device *dev);

static void do_ata_cmd(struct device *dev, struct queue_item *q);
static void do_cfg_cmd(struct device *dev, struct queue_item *q);
static void do_macmask_cmd(struct device *dev, struct queue_item *q);
static void do_reserve_cmd(struct device *dev, struct queue_item *q);

static void trace_ata(const struct device *dev, const struct queue_item *q);
static void trace_cfg(const struct device *dev, const struct queue_item *q);
static void trace_macmask(const struct device *dev, const struct queue_item *q);
static void trace_reserve(const struct device *dev, const struct queue_item *q);

/**********************************************************************
 * Global variables
 */

/* List of all configured devices */
GPtrArray *devices;

#define ATACMD(x) [WIN_ ## x] = #x
static const char *const ata_cmds[256] =
{
	ATACMD(READ),
	ATACMD(READ_EXT),
	ATACMD(WRITE),
	ATACMD(WRITE_EXT),
	ATACMD(PACKETCMD),
	ATACMD(SMART),
	ATACMD(FLUSH_CACHE),
	ATACMD(FLUSH_CACHE_EXT),
	ATACMD(IDENTIFY)
};

#define CFGCMD(x) [AOE_CFG_ ## x] = #x
static const char *const cfg_cmds[16] =
{
	CFGCMD(READ),
	CFGCMD(TEST),
	CFGCMD(TEST_PREFIX),
	CFGCMD(SET),
	CFGCMD(FORCE_SET)
};

#define MACMASKCMD(x) [AOE_MCMD_ ## x] = #x
static const char *const macmask_cmds[256] =
{
	MACMASKCMD(READ),
	MACMASKCMD(EDIT)
};

#define RESERVECMD(x) [AOE_RESERVE_ ## x] = #x
static const char *const reserve_cmds[256] =
{
	RESERVECMD(READ),
	RESERVECMD(SET),
	RESERVECMD(FORCESET)
};

struct cmd_info
{
	unsigned header_length;
	void (*process)(struct device *dev, struct queue_item *q);
	void (*trace)(const struct device *dev, const struct queue_item *q);
};

static const struct cmd_info aoe_cmds[] =
{
	[AOE_CMD_ATA] =
	{
		sizeof(struct aoe_ata_hdr),
		do_ata_cmd,
		trace_ata
	},
	[AOE_CMD_CFG] =
	{
		sizeof(struct aoe_cfg_hdr),
		do_cfg_cmd,
		trace_cfg
	},
	[AOE_CMD_MASK] =
	{
		sizeof(struct aoe_macmask_hdr),
		do_macmask_cmd,
		trace_macmask
	},
	[AOE_CMD_RESERVE] =
	{
		sizeof(struct aoe_reserve_hdr),
		do_reserve_cmd,
		trace_reserve
	},
};

static GQueue active_devs;

/**********************************************************************
 * Misc. helpers
 */

static struct queue_item *new_request(struct device *dev, struct netif *iface,
	void *buf, unsigned length, const struct timespec *tv)
{
	struct queue_item *q;

	q = g_slice_new0(struct queue_item);
	q->dev = dev;
	q->iface = iface;
	q->buf = buf;
	q->bufsize = iface->mtu;
	q->length = length;

	if (tv)
		q->start = *tv;
	else
		clock_gettime(CLOCK_REALTIME, &q->start);

	++dev->queue_length;

	return q;
}

static struct queue_item *queue_get(struct device *dev, struct netif *iface,
	void *buf, unsigned length, const struct timespec *tv)
{
	if (dev->queue_length >= dev->cfg.queue_length)
		return NULL;

	dev->stats.queue_length += dev->queue_length;
	return new_request(dev, iface, buf, length, tv);
}

/* Invalidate the buffer of the request */
static inline void drop_buffer(struct queue_item *q)
{
	if (q->dynalloc)
	{
		free_packet(q->buf, q->bufsize);
		q->dynalloc = 0;
	}
	q->length = 0;
}

static inline void timespec_sub(const struct timespec *a,
	const struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (res->tv_nsec < 0)
	{
		res->tv_nsec += 1000000000;
		--res->tv_sec;
	}
}

static inline void timespec_add(const struct timespec *a,
	const struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_nsec = a->tv_nsec + b->tv_nsec;
	if (res->tv_nsec >= 1000000000)
	{
		res->tv_nsec -= 1000000000;
		++res->tv_sec;
	}
}

/* Drop a request without sending a reply */
void drop_request(struct queue_item *q)
{
	struct timespec now, len;

	drop_buffer(q);
	if (q->dev)
	{
		struct device *const dev = q->dev;

		--dev->queue_length;

		/* Update queue statistics */
		if (q->start.tv_sec)
		{
			clock_gettime(CLOCK_REALTIME, &now);
			timespec_sub(&now, &q->start, &len);
			timespec_add(&dev->stats.req_time, &len, &dev->stats.req_time);
		}
	}
	g_slice_free(struct queue_item, q);
}

/* Copy the contents of the original request to a dynamically allocated buffer */
static int clone_pkt(struct queue_item *q)
{
	void *pkt;

	pkt = alloc_packet(q->bufsize);
	if (!pkt)
		return -1;
	memcpy(pkt, q->buf + q->hdrlen, q->length - q->hdrlen);
	q->length -= q->hdrlen;
	q->buf = pkt;
	q->dynalloc = TRUE;
	return 0;
}

static inline unsigned max_sect_nr(const struct netif *iface)
{
	return (iface->mtu - sizeof(struct aoe_ata_hdr)) >> 9;
}

/**********************************************************************
 * Allocate/deallocate devices
 */

static void free_dev(struct device *dev)
{
	g_free(dev->name);
	if (dev->fd != -1)
		close(dev->fd);
	if (dev->event_fd != -1)
	{
		del_fd(dev->event_fd);
		close(dev->event_fd);
	}
	if (dev->timer_fd != -1)
	{
		del_fd(dev->timer_fd);
		close(dev->timer_fd);
	}

	if (dev->aoe_conf && dev->aoe_conf != MAP_FAILED)
		munmap(dev->aoe_conf, sizeof(*dev->aoe_conf));
	if (dev->mac_mask && dev->mac_mask != MAP_FAILED)
		munmap(dev->mac_mask, sizeof(*dev->mac_mask));
	if (dev->reserve && dev->reserve != MAP_FAILED)
		munmap(dev->reserve, sizeof(*dev->reserve));

	g_ptr_array_free(dev->ifaces, TRUE);
	g_ptr_array_free(dev->deferred, TRUE);
	destroy_device_config(&dev->cfg);
	g_slice_free(struct device, dev);
}

static void *open_and_map(struct device *dev, const char *suffix, size_t length)
{
	char *filename;
	void *addr;
	int fd;

	filename = g_strdup_printf("%s/%s.%s", defaults.statedir, dev->name, suffix);
	fd = open(filename, O_RDWR | O_CREAT, 0600);
	if (fd == -1)
	{
		deverr(dev, "Failed to open/create %s", filename);
		g_free(filename);
		return MAP_FAILED;
	}

	if (ftruncate(fd, length))
	{
		deverr(dev, "Failed to extend %s", filename);
		close(fd);
		g_free(filename);
		return MAP_FAILED;
	}

	addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED)
		deverr(dev, "Failed to map %s to memory", filename);

	close(fd);
	g_free(filename);
	return addr;
}

static void check_config_map(const struct device *dev, struct config_map *map)
{
	if (map->magic == CONFIG_MAP_MAGIC && map->length <= 1024)
		return;
	devlog(dev, LOG_WARNING, "Resetting AoE configuration space");
	memset(map, 0, sizeof(*map));
	map->magic = CONFIG_MAP_MAGIC;
	msync(map, sizeof(*map), MS_ASYNC);
}

static void check_acl_map(const struct device *dev, struct acl_map *map, const char *msg)
{
	if (map->magic == ACL_MAP_MAGIC && map->length <= 255)
		return;
	devlog(dev, LOG_WARNING, "Resetting AoE %s list", msg);
	memset(map, 0, sizeof(*map));
	map->magic = ACL_MAP_MAGIC;
	msync(map, sizeof(*map), MS_ASYNC);
}

static struct device *alloc_dev(const char *name)
{
	unsigned long long hsize;
	struct device *dev;
	const char *unit;
	struct stat st;
	int ret, flags;
	unsigned i;

	dev = g_slice_new0(struct device);
	dev->name = g_strdup(name);
	dev->fd = -1;
	dev->event_fd = -1;
	dev->timer_fd = -1;
	dev->ifaces = g_ptr_array_new();
	dev->event_ctx.callback = dev_io;
	dev->event_ctx.data = dev;
	dev->timer_ctx.callback = dev_timer;
	dev->timer_ctx.data = dev;
	dev->chain.data = dev;

	if (!get_device_config(name, &dev->cfg))
	{
		free_dev(dev);
		return NULL;
	}

	dev->deferred = g_ptr_array_sized_new(dev->cfg.queue_length);

	for (i = 0; i < devices->len; i++)
	{
		struct device *dev2 = g_ptr_array_index(devices, i);
		if (dev2 == dev)
			continue;
		if (dev2->cfg.shelf != dev->cfg.shelf || dev2->cfg.slot != dev->cfg.slot)
			continue;
		devlog(dev, LOG_ERR, "Duplicate shelf/slot (matches %s)", dev2->name);
		free_dev(dev);
		return NULL;
	}

	ret = io_setup(dev->cfg.queue_length, &dev->aio_ctx);
	if (ret)
	{
		if (ret == -EAGAIN)
		{
			devlog(dev, LOG_ERR, "Failed to allocate the AIO context.");
			devlog(dev, LOG_ERR, "Consider increasing /proc/sys/fs/aio-max-nr");
		}
		else
			devlog(dev, LOG_ERR, "io_setup() failed: %s", strerror(-ret));
		free_dev(dev);
		return NULL;
	}

	dev->event_fd = eventfd(0, EFD_NONBLOCK);
	if (dev->event_fd == -1)
	{
		deverr(dev, "Failed to create eventfd");
		free_dev(dev);
		return NULL;
	}
	add_fd(dev->event_fd, &dev->event_ctx);

	if (dev->cfg.merge_delay)
	{
		dev->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
		if (dev->timer_fd == -1)
			deverr(dev, "Failed to create timerfd, merge-delay disabled");
		else
			add_fd(dev->timer_fd, &dev->timer_ctx);
	}

	if (stat(dev->cfg.path, &st))
	{
		deverr(dev, "stat('%s') failed", dev->cfg.path);
		free_dev(dev);
		return NULL;
	}

	if (!S_ISBLK(st.st_mode) && !S_ISREG(st.st_mode))
	{
		devlog(dev, LOG_ERR, "Not a device or regular file");
		free_dev(dev);
		return NULL;
	}

	flags = dev->cfg.read_only ? O_RDONLY : O_RDWR;
	if (dev->cfg.direct_io)
		flags |= O_DIRECT;
	/* Open block devices in exclusive mode */
	if (S_ISBLK(st.st_mode))
		flags |= O_EXCL;

	dev->fd = open(dev->cfg.path, flags);
	if (dev->fd == -1)
	{
		deverr(dev, "Failed to open '%s'", dev->cfg.path);
		free_dev(dev);
		return NULL;
	}

	if (S_ISBLK(st.st_mode))
	{
		if (ioctl(dev->fd, BLKGETSIZE64, &dev->size))
		{
			deverr(dev, "ioctl(BLKGETSIZE64) failed");
			free_dev(dev);
			return NULL;
		}
	}
	else
		dev->size = st.st_size;

	dev->aoe_conf = open_and_map(dev, "config", sizeof(*dev->aoe_conf));
	dev->mac_mask = open_and_map(dev, "mac_mask", sizeof(*dev->mac_mask));
	dev->reserve = open_and_map(dev, "reserve", sizeof(*dev->reserve));
	if (dev->aoe_conf == MAP_FAILED || dev->mac_mask == MAP_FAILED ||
			dev->reserve == MAP_FAILED)
	{
		free_dev(dev);
		return NULL;
	}

	check_config_map(dev, dev->aoe_conf);
	check_acl_map(dev, dev->mac_mask, "MAC Mask");
	check_acl_map(dev, dev->reserve, "Reserve");

	hsize = human_format(dev->size, &unit);
	devlog(dev, LOG_INFO, "Shelf %d, slot %d, path '%s' (size %lld %s, sectors %lld) opened%s%s",
		ntohs(dev->cfg.shelf), dev->cfg.slot, dev->cfg.path, hsize, unit,
		(long long)dev->size >> 9,
		dev->cfg.read_only ? " R/O" : "",
		dev->cfg.direct_io ? ", using direct I/O" : "");

	return dev;
}

/* Check if the change in configuration requires re-opening the device */
static int reopen_needed(const struct device *dev)
{
	struct device_config newcfg;
	int reopen = FALSE;

	if (!get_device_config(dev->name, &newcfg))
		return FALSE;

	/* Check compatibility of old and new fields */
	if (dev->cfg.path && strcmp(dev->cfg.path, newcfg.path))
		reopen = TRUE;
	if (dev->cfg.queue_length != newcfg.queue_length)
		reopen = TRUE;
	if (dev->cfg.read_only != newcfg.read_only)
		reopen = TRUE;

	destroy_device_config(&newcfg);

	return reopen;
}

/* Re-configure a device */
static void setup_dev(struct device *dev)
{
	struct device_config newcfg;
	unsigned long long size;
	struct stat st;
	int ret;

	if (!get_device_config(dev->name, &newcfg))
		return;

	if (dev->cfg.direct_io != newcfg.direct_io)
	{
		long flags = fcntl(dev->fd, F_GETFL);
		if (newcfg.direct_io)
			flags |= O_DIRECT;
		else
			flags &= ~O_DIRECT;
		if (fcntl(dev->fd, F_SETFL, flags))
		{
			deverr(dev, "Failed to change direct I/O settings");
			newcfg.direct_io = dev->cfg.direct_io;
		}
		else
			devlog(dev, LOG_INFO, "%s direct I/O from now on",
				newcfg.direct_io ? "Using" : "Not using");
	}

	if (newcfg.merge_delay && dev->timer_fd == -1)
	{
		dev->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
		if (dev->timer_fd == -1)
			deverr(dev, "Failed to create timerfd, merge-delay disabled");
		else
			add_fd(dev->timer_fd, &dev->timer_ctx);
	}
	if (!newcfg.merge_delay && dev->timer_fd != -1)
	{
		del_fd(dev->timer_fd);
		close(dev->timer_fd);
		dev->timer_fd = -1;
	}

	destroy_device_config(&dev->cfg);
	dev->cfg = newcfg;

	ret = fstat(dev->fd, &st);
	if (ret)
	{
		deverr(dev, "fstat() failed");
		return;
	}
	if (S_ISBLK(st.st_mode))
	{
		if (ioctl(dev->fd, BLKGETSIZE64, &size))
		{
			deverr(dev, "ioctl(BLKGETSIZE64) failed");
			return;
		}
	}
	else
		size = st.st_size;

	if (size != dev->size)
	{
		unsigned long long hsize;
		const char *unit;

		hsize = human_format(size, &unit);
		devlog(dev, LOG_INFO, "New size %lld (%lld sectors)",
			hsize, size >> 9);
		dev->size = size;
	}
}

/**********************************************************************
 * I/O handling
 */

/* Called when a request has been finished and a reply should be sent */
static void finish_request(struct queue_item *q, int error)
{
	struct device *const dev = q->dev;

	q->aoe_hdr.error = error;
	if (error)
	{
		q->hdrlen = sizeof(struct aoe_hdr);
		q->aoe_hdr.is_error = TRUE;
		++dev->stats.proto_err;
	}

	/* This can happen if the interface went down while the I/O was still
	 * in progress */
	if (!q->iface)
		return drop_request(q);

	if (G_UNLIKELY(dev->cfg.trace_io))
		devlog(dev, LOG_DEBUG, "%s/%08x: Completed, status %d",
			ether_ntoa((struct ether_addr *)&q->aoe_hdr.addr.ether_shost),
			(uint32_t)ntohl(q->aoe_hdr.tag), error);

	/* Swap the source/destination addresses */
	memcpy(&q->aoe_hdr.addr.ether_dhost, &q->aoe_hdr.addr.ether_shost, ETH_ALEN);
	memcpy(&q->aoe_hdr.addr.ether_shost, &q->iface->mac, ETH_ALEN);

	/* Always supply our own shelf/slot address in case the request was a broadcast */
	q->aoe_hdr.shelf = dev->cfg.shelf;
	q->aoe_hdr.slot = dev->cfg.slot;

	/* Mark the packet as a response */
	q->aoe_hdr.is_response = TRUE;

	send_response(q);
}

/* Finish an ATA command */
static void finish_ata(struct queue_item *q, int error, int status)
{
	q->ata_hdr.err_feature = error;
	q->ata_hdr.cmdstat = status;
	if (status & ATA_ERR)
	{
		drop_buffer(q);
		++q->dev->stats.ata_err;
	}
	finish_request(q, 0);
}

/* Called when an I/O event completes */
static void complete_io(struct submit_slot *s, long res)
{
	int error, status;
	unsigned i;

	g_queue_unlink(&s->dev->active, &s->chain);

	if (G_UNLIKELY(res < 0))
	{
		devlog(s->dev, LOG_ERR, "%s request failed: %s",
			s->iocb.aio_lio_opcode == IO_CMD_PREADV ? "Read" : "Write",
			strerror(-res));
		error = res == -EIO ? ATA_UNC : ATA_ABORTED;
		status = ATA_ERR | ATA_DRDY;
	}
	else
	{
		error = 0;
		status = ATA_DRDY;
	}

	for (i = 0; i < s->num_iov; i++)
	{
		struct queue_item *q = s->items[i];

		/* Check if we got less data than we wanted */
		if (G_UNLIKELY(!res))
		{
			devlog(q->dev, LOG_ERR, "Short %s request",
				s->iocb.aio_lio_opcode == IO_CMD_PREADV ? "read" : "write");
			error = ATA_ABORTED;
			status |= ATA_ERR;
		}
		res -= q->length;

		/* Do not send back the data to the client in case of a write
		 * request */
		if (s->iocb.aio_lio_opcode == IO_CMD_PWRITEV)
			q->length = 0;

		finish_ata(q, error, status);
	}
	g_slice_free(struct submit_slot, s);
}

static void activate_dev(struct device *dev)
{
	struct itimerspec new, old;

	if (dev->is_active)
		return;

	dev->is_active = TRUE;

	if (dev->timer_fd != -1 && dev->cfg.merge_delay)
	{
		memset(&new, 0, sizeof(new));
		new.it_value.tv_nsec = dev->cfg.merge_delay;
		if (timerfd_settime(dev->timer_fd, 0, &new, &old))
			deverr(dev, "Failed to arm timer");
		else if (G_UNLIKELY(dev->cfg.trace_io))
			devlog(dev, LOG_DEBUG, "Timer armed");
	}
	else
		g_queue_push_tail_link(&active_devs, &dev->chain);
}

static void deactivate_dev(struct device *dev)
{
	if (!dev->is_active)
		return;

	if (dev->timer_fd == -1)
		g_queue_unlink(&active_devs, &dev->chain);
	dev->is_active = FALSE;
}

/* eventfd event handler callback */
static void dev_io(uint32_t events, void *data)
{
	struct device *const dev = data;
	struct io_event ev[EVENT_BATCH];
	eventfd_t dummy;
	int ret, i;

	/* Reset the event counter */
	if (events & EPOLLIN)
	{
		ret = read(dev->event_fd, &dummy, sizeof(dummy));
		if (ret != sizeof(dummy))
			devlog(dev, LOG_WARNING, "Short read on the eventfd");
	}

	while (dev->active.length)
	{
		ret = io_getevents(dev->aio_ctx, 0, EVENT_BATCH, ev, NULL);
		if (ret < 0)
		{
			devlog(dev, LOG_ERR, "io_getevents() failed: %s",
				strerror(-ret));
			break;
		}

		for (i = 0; i < ret; i++)
			complete_io(ev[i].data, ev[i].res);

		if (ret < EVENT_BATCH)
			break;
		++dev->stats.dev_io_max_hit;
	}

	deactivate_dev(dev);
	run_queue(dev);
}

/* timerfd callback */
void dev_timer(uint32_t events, void *data)
{
	struct device *const dev = data;
	uint64_t expires;
	int ret;

	if (G_UNLIKELY(dev->cfg.trace_io))
		devlog(dev, LOG_DEBUG, "Timer expired");

	ret = read(dev->timer_fd, &expires, sizeof(expires));
	if (ret == -1)
	{
		if (ret != EAGAIN)
			deverr(dev, "Timer read");
		return;
	}

	deactivate_dev(dev);
	run_queue(dev);
}

#define CMP(a, b) ((a) < (b) ? -1 : ((a) > (b) ? 1 : 0))
static int queue_compare(const void *a, const void *b)
{
	const struct queue_item *aa = *(void **)a, *bb = *(void **)b;
	long t;

	if (aa->start.tv_sec != bb->start.tv_sec)
		return CMP(aa->start.tv_sec, bb->start.tv_sec);
	t = aa->start.tv_nsec - bb->start.tv_nsec;
	if (abs(t) > aa->dev->cfg.max_delay)
		return t;
	return CMP(aa->offset, bb->offset);
}

/* Set up the iocb for submission */
static inline void prepare_io(struct submit_slot *s)
{
	if (s->is_write)
		io_prep_pwritev(&s->iocb, s->dev->fd, s->iov, s->num_iov, s->offset);
	else
		io_prep_preadv(&s->iocb, s->dev->fd, s->iov, s->num_iov, s->offset);
	s->iocb.data = s;
	io_set_eventfd(&s->iocb, s->dev->event_fd);
}

static void submit(struct device *dev)
{
	struct iocb *iocbs[EVENT_BATCH];
	unsigned i, num_iocbs, req_prep;
	unsigned long long next_offset;
	struct submit_slot *s;
	struct queue_item *q;
	int ret;

	/* Sort the deferred queue so we can merge more (we hope) */
	g_ptr_array_sort(dev->deferred, queue_compare);

	s = NULL;
	num_iocbs = 0;
	next_offset = 0ull;
	req_prep = 0;

	while (1)
	{
		/* Add a guard element to force flushing the last slot */
		if (req_prep < dev->deferred->len)
			q = g_ptr_array_index(dev->deferred, req_prep);
		else
			q = NULL;

		/* - If there is already an open slot, and
		 *   - either nothing is left in the queue, or
		 *   - the next item cannot be merged into the current slot,
		 * then flush the current slot and go for a new one. */
		if (s && (!q ||
				q->is_write != s->is_write ||
				q->offset != next_offset ||
				s->num_iov >= G_N_ELEMENTS(s->iov)))
		{
			if (G_UNLIKELY(dev->cfg.trace_io))
				devlog(dev, LOG_DEBUG, "Flush slot, requests: %u", s->num_iov);

			prepare_io(s);
			iocbs[num_iocbs++] = &s->iocb;
			s = NULL;

			/* This is the real exit from the loop */
			if (!q || num_iocbs >= G_N_ELEMENTS(iocbs))
				break;
		}

		if (!s)
		{
			s = g_slice_new0(struct submit_slot);
			s->chain.data = s;
			s->dev = dev;

			s->is_write = q->is_write;
			next_offset = s->offset = q->offset;

			if (G_UNLIKELY(dev->cfg.trace_io))
				devlog(dev, LOG_DEBUG, "New %s slot, offset %llu, size %u",
					q->is_write ? "write" : "read", q->offset, q->length);
		}

		s->iov[s->num_iov].iov_base = q->buf;
		s->iov[s->num_iov].iov_len = q->length;
		s->items[s->num_iov] = q;
		if (s->num_iov++)
			++dev->stats.queue_merge;
		next_offset += q->length;
		++req_prep;
	}

	ret = io_submit(dev->aio_ctx, num_iocbs, iocbs);
	if (ret == -EAGAIN)
	{
		for (i = 0; i < num_iocbs; i++)
			g_slice_free(struct submit_slot, iocbs[i]->data);
		dev->io_stall = TRUE;
		++dev->stats.queue_stall;
		return;
	}
	else if (ret < 0)
	{
		devlog(dev, LOG_ERR, "Failed to submit I/O: %s", strerror(-ret));
		for (i = 0; i < num_iocbs; i++)
			g_slice_free(struct submit_slot, iocbs[i]->data);
		for (i = 0; i < req_prep; i++)
		{
			q = g_ptr_array_index(dev->deferred, i);
			finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
		}
		g_ptr_array_remove_range(dev->deferred, 0, req_prep);
		return;
	}

	/* Add the submitted requests to the active queue */
	for (i = 0; i < (unsigned)ret; i++)
	{
		s = iocbs[i]->data;
		g_queue_push_tail_link(&dev->active, &s->chain);
	}
	g_ptr_array_remove_range(dev->deferred, 0, req_prep);
}

static void run_queue(struct device *dev)
{
	/* Submit any prepared I/Os */
	dev->io_stall = FALSE;
	while (dev->deferred->len && !dev->io_stall)
		submit(dev);
}

void run_devices(void)
{
	GList *l;

	while ((l = g_queue_pop_head_link(&active_devs)))
	{
		struct device *dev = l->data;

		dev->is_active = FALSE;
		run_queue(dev);
	}
}

static void ata_rw(struct queue_item *q)
{
	struct device *const dev = q->dev;

	/* Check for reservations */
	if (dev->reserve->length && !match_acl(dev->reserve,
			&q->aoe_hdr.addr.ether_shost))
		return finish_request(q, AOE_ERR_RESERVED);

	if (G_UNLIKELY(q->ata_hdr.nsect > max_sect_nr(q->iface)))
	{
		devlog(dev, LOG_ERR, "Request too large (%d)", q->ata_hdr.nsect);
		return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
	}
	if (G_UNLIKELY(q->is_write && q->length < (unsigned)q->ata_hdr.nsect << 9))
	{
		devlog(dev, LOG_ERR, "Short write request (have %u, requested %u)",
			q->length, (unsigned)q->ata_hdr.nsect << 9);
		return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
	}

	q->length = (unsigned)q->ata_hdr.nsect << 9;

	if (G_UNLIKELY(q->offset + q->length > dev->size))
	{
		devlog(dev, LOG_NOTICE, "Attempt to access beyond end-of-device");
		return finish_ata(q, ATA_IDNF, ATA_DRDY | ATA_ERR);
	}

	if (q->is_write)
	{
		dev->stats.write_bytes += q->length;
		++dev->stats.write_req;
	}
	else
	{
		dev->stats.read_bytes += q->length;
		++dev->stats.read_req;
	}

	/* If there are any deferred requests, then mark the device as active
	 * to ensure run_queue() will get called */
	g_ptr_array_add(dev->deferred, q);
	activate_dev(dev);
}

static void set_string(char *dst, const char *src, unsigned dstlen)
{
	unsigned len;
	char tmp;

	len = strlen(src);
	if (len > dstlen)
		len = dstlen;
	memcpy(dst, src, len);
	memset(dst + len, ' ', dstlen - len);

	/* Swapping is required for ATA strings */
	for (len = 0; len < dstlen; len += 2)
	{
		tmp = dst[len];
		dst[len] = dst[len + 1];
		dst[len + 1] = tmp;
	}
}

static void do_identify(struct queue_item *q)
{
	struct hd_driveid *ident;

	if (q->ata_hdr.nsect != 1)
	{
		devlog(q->dev, LOG_ERR, "Unexpected sector number (%hhd) for IDENTIFY", q->ata_hdr.nsect);
		return finish_request(q, AOE_ERR_BADARG);
	}

	++q->dev->stats.other_req;

	ident = q->buf;
	memset(ident, 0, sizeof(*ident));
	q->length = 512;

	set_string((char *)ident->serial_no, q->dev->name, sizeof(ident->serial_no));
	set_string((char *)ident->fw_rev, PACKAGE_VERSION, sizeof(ident->fw_rev));
	set_string((char *)ident->model, PACKAGE_NAME, sizeof(ident->model));

	ident->dword_io = GUINT16_TO_LE(1);

	/* LBA */
	ident->capability = GUINT16_TO_LE(2);

	/* Legacy CHS if anyone still wants it */
	ident->cur_cyls = (q->dev->size >> 9) / (255 * 16);
	if (ident->cur_cyls > 16383)
		ident->cur_cyls = 16383;
	ident->cur_cyls = GUINT16_TO_LE(ident->cur_cyls);
	ident->cur_heads = GUINT16_TO_LE(16);
	ident->cur_sectors = GUINT16_TO_LE(255);

	if (q->dev->size >> 9 > MAX_LBA28)
		ident->lba_capacity = GUINT32_TO_LE(MAX_LBA28);
	else
		ident->lba_capacity = GUINT32_TO_LE(q->dev->size >> 9);

	/* Bit 14: must be 1, bit 13: FLUSH_CACHE_EXT, bit 12: FLUSH_CACHE, bit 10: LBA48 */
#if 0
	ident->command_set_2 = GUINT16_TO_LE((1 << 14) | (1 << 13) | (1 << 12) | (1 << 10));
#else
	ident->command_set_2 = GUINT16_TO_LE((1 << 14) | (1 << 10));
#endif
	/* Bit 14: must be 1 */
	ident->cfsse = GUINT16_TO_LE(1 << 14);
	/* Bit 14: must be 1, bit 13: FLUSH_CACHE_EXT, bit 12: FLUSH_CACHE, bit 10: LBA48 */
#if 0
	ident->cfs_enable_2 = GUINT16_TO_LE((1 << 14) | (1 << 13) | (1 << 12) | (1 << 10));
#else
	ident->cfs_enable_2 = GUINT16_TO_LE((1 << 14) | (1 << 10));
#endif
	/* Bit 14: must be 1 */
	ident->csf_default = GUINT16_TO_LE(1 << 14);
	/* Bit 14: must be 1, bit 3: device 0 passed diag, bit 2-1: 01 - jumper, bit 0: must be 1 */
	ident->hw_config = GUINT16_TO_LE(0x400b);

	ident->lba_capacity_2 = GUINT64_TO_LE(q->dev->size >> 9);

	q->ata_hdr.err_feature = 0;
	q->ata_hdr.cmdstat = ATA_DRDY;

	finish_request(q, 0);
}

static unsigned long long get_lba(const struct aoe_ata_hdr *pkt)
{
	unsigned long long lba;
	unsigned i;

	lba = 0;
	for (i = 0; i < 6; i++)
		lba |= pkt->lba[i] << (i * 8);
	if (!pkt->is_lba48)
		lba &= MAX_LBA28;
	return lba;
}

static void trace_ata(const struct device *dev, const struct queue_item *q)
{
	const struct aoe_ata_hdr *pkt = &q->ata_hdr;
	unsigned long long lba;
	const char *cmd;
	char buf[16];

	cmd = ata_cmds[pkt->cmdstat];
	if (!cmd)
	{
		snprintf(buf, sizeof(buf), "Unknown (%02x)", pkt->cmdstat);
		cmd = buf;
	}

	lba = get_lba(pkt);

	devlog(dev, LOG_DEBUG, "%s/%08x: Received ATA cmd %s, LBA%s %llu, sect %u [%c%c%c]",
		ether_ntoa((struct ether_addr *)&pkt->aoehdr.addr.ether_shost),
		(uint32_t)ntohl(pkt->aoehdr.tag), cmd,
		pkt->is_lba48 ? "48" : "28", lba,
		(unsigned)pkt->nsect,
		pkt->devhead ? 'D' : ' ',
		pkt->is_async ? 'A' : ' ',
		pkt->is_write ? 'W' : ' ');
}

static void do_ata_cmd(struct device *dev, struct queue_item *q)
{
	unsigned long long lba;

	lba = get_lba(&q->ata_hdr);

	switch (q->ata_hdr.cmdstat)
	{
		case WIN_READ:
		case WIN_READ_EXT:
			q->is_write = 0;
			q->offset = lba << 9;
			return ata_rw(q);
		case WIN_WRITE:
		case WIN_WRITE_EXT:
			if (q->dev->cfg.read_only)
				return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
			q->is_write = 1;
			q->offset = lba << 9;
			return ata_rw(q);
		case WIN_IDENTIFY:
			return do_identify(q);
#if 0
		case WIN_FLUSH_CACHE:
		case WIN_FLUSH_CACHE_EXT:
			/* Ideally we would queue an IOCB_CMD_FSYNC command but
			 * nothing seems to implement it, so this is a cheap
			 * workaround */
			q->state = FLUSH;
			drop_buffer(q);
			++dev->stats.other_req;

			/* We have to be careful: if the flush is the only
			 * request in the queue, then we have to flush the
			 * queue to avoid a stall */
			if (dev->q_tail - dev->q_head == 1)
				run_queue(dev);
			return;
#endif
		case WIN_CHECKPOWERMODE1:
			q->ata_hdr.cmdstat = ATA_DRDY;
			q->ata_hdr.err_feature = 0;
			q->ata_hdr.nsect = 0xff; /* Active/idle */
			drop_buffer(q);
			++dev->stats.other_req;
			return finish_request(q, 0);
		default:
			devlog(dev, LOG_WARNING, "Unimplemented ATA command: %02x", q->ata_hdr.cmdstat);
			return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
	}
}

static void trace_cfg(const struct device *dev, const struct queue_item *q)
{
	const struct aoe_cfg_hdr *pkt = &q->cfg_hdr;
	const char *cmd;
	char buf[16];

	cmd = cfg_cmds[pkt->ccmd];
	if (!cmd)
	{
		snprintf(buf, sizeof(buf), "Unknown (%02x)", pkt->ccmd);
		cmd = buf;
	}

	devlog(dev, LOG_DEBUG, "%s/%08x: Received CFG cmd %s",
		ether_ntoa((struct ether_addr *)&pkt->aoehdr.addr.ether_shost),
		(uint32_t)ntohl(pkt->aoehdr.tag), cmd);
}

static void do_cfg_cmd(struct device *dev, struct queue_item *q)
{
	unsigned len;

	len = ntohs(q->cfg_hdr.cfg_len);
	if (len > q->length)
	{
		devlog(dev, LOG_ERR, "Short CFG request on %s", q->iface->name);
		return finish_request(q, AOE_ERR_BADARG);
	}
	if (len > 1024)
	{
		devlog(dev, LOG_ERR, "Config string length too long (%u)", len);
		return finish_request(q, AOE_ERR_BADARG);
	}

	++dev->stats.other_req;
	switch (q->cfg_hdr.ccmd)
	{
		case AOE_CFG_READ:
			break;
		case AOE_CFG_TEST:
			if (len != dev->aoe_conf->length)
				return drop_request(q);
			/* Fall through */
		case AOE_CFG_TEST_PREFIX:
			if (len > dev->aoe_conf->length ||
					memcmp(q->buf, &dev->aoe_conf->data, len))
				return drop_request(q);
			break;
		case AOE_CFG_SET:
			if (dev->aoe_conf->length && (dev->aoe_conf->length != len ||
					memcmp(q->buf, &dev->aoe_conf->data, len)))
				return finish_request(q, AOE_ERR_CFG_SET);
			/* Fall through */
		case AOE_CFG_FORCE_SET:
			memcpy(&dev->aoe_conf->data, q->buf, len);
			dev->aoe_conf->length = len;
			msync(dev->aoe_conf, sizeof(*dev->aoe_conf), MS_ASYNC);
			break;
		default:
			return finish_request(q, AOE_ERR_BADARG);
	}

	q->cfg_hdr.queuelen = htons(dev->cfg.queue_length);
	q->cfg_hdr.firmware = 1;
	q->cfg_hdr.maxsect = max_sect_nr(q->iface);
	q->cfg_hdr.version = AOE_VERSION;

	len = dev->aoe_conf->length;
	q->cfg_hdr.cfg_len = htons(len);

	drop_buffer(q);
	if (len)
	{
		if (len > q->bufsize)
			len = q->bufsize;
		q->buf = &dev->aoe_conf->data;
		q->length = len;
	}

	finish_request(q, 0);
}

static void trace_macmask(const struct device *dev, const struct queue_item *q)
{
	const struct aoe_macmask_hdr *pkt = &q->mask_hdr;
	const char *cmd;
	char buf[16];

	cmd = macmask_cmds[pkt->mcmd];
	if (!cmd)
	{
		snprintf(buf, sizeof(buf), "Unknown (%02x)", pkt->mcmd);
		cmd = buf;
	}

	devlog(dev, LOG_DEBUG, "%s/%08x: Received MAC mask cmd %s",
		ether_ntoa((struct ether_addr *)&pkt->aoehdr.addr.ether_shost),
		(uint32_t)ntohl(pkt->aoehdr.tag), cmd);
}

static void do_macmask_cmd(struct device *dev, struct queue_item *q)
{
	struct aoe_macmask_dir *dir = q->buf;
	unsigned i;

	q->mask_hdr.merror = 0;
	q->mask_hdr.reserved = 0;

	if (q->length < q->mask_hdr.dcnt * sizeof(struct aoe_macmask_dir))
	{
		devlog(dev, LOG_ERR, "Short MAC mask request on %s", q->iface->name);
		return finish_request(q, AOE_ERR_BADARG);
	}

	++q->dev->stats.other_req;

	switch (q->mask_hdr.mcmd)
	{
		case AOE_MCMD_READ:
		case AOE_MCMD_EDIT:
			break;
		default:
			devlog(dev, LOG_ERR, "Unknown MAC mask subcommand %d", q->mask_hdr.mcmd);
			return finish_request(q, AOE_ERR_BADARG);
	}

	if (q->mask_hdr.mcmd == AOE_MCMD_EDIT)
	{
		for (i = 0; i < q->mask_hdr.dcnt; i++)
		{
			switch (dir[i].dcmd)
			{
				case AOE_DCMD_NONE:
					break;
				case AOE_DCMD_ADD:
					if (add_one_acl(dev->mac_mask, &dir[i].addr))
						q->mask_hdr.merror = AOE_MERROR_FULL;
					break;
				case AOE_DCMD_DELETE:
					del_one_acl(dev->mac_mask, &dir[i].addr);
					break;
				default:
					q->mask_hdr.merror = AOE_MERROR_BADDIR;
			}

			if (q->mask_hdr.merror)
				break;
		}

		/* Make sure the changes eventually hit the disk */
		msync(dev->mac_mask, sizeof(*dev->mac_mask), MS_ASYNC);
		if (i < q->mask_hdr.dcnt)
		{
			q->mask_hdr.dcnt = i;
			return finish_request(q, 0);
		}
	}

	/* Fill the result with the current MAC mask list */
	q->mask_hdr.dcnt = dev->mac_mask->length;
	for (i = 0; i < dev->mac_mask->length; i++)
	{
		dir[i].reserved = 0;
		dir[i].dcmd = AOE_DCMD_NONE;
		memcpy(&dir[i].addr, &dev->mac_mask->entries[i].e, ETH_ALEN);
	}
	q->length = i * sizeof(*dir);

	return finish_request(q, 0);
}

static void trace_reserve(const struct device *dev, const struct queue_item *q)
{
	const struct aoe_reserve_hdr *pkt = &q->reserve_hdr;
	const char *cmd;
	char buf[16];

	cmd = reserve_cmds[pkt->rcmd];
	if (!cmd)
	{
		snprintf(buf, sizeof(buf), "Unknown (%02x)", pkt->rcmd);
		cmd = buf;
	}

	devlog(dev, LOG_DEBUG, "%s/%08x: Received Reserve cmd %s",
		ether_ntoa((struct ether_addr *)&pkt->aoehdr.addr.ether_shost),
		(uint32_t)ntohl(pkt->aoehdr.tag), cmd);
}

static void do_reserve_cmd(struct device *dev, struct queue_item *q)
{
	struct ether_addr *addrs = q->buf;
	unsigned i;

	if (q->length < q->reserve_hdr.nmacs * sizeof(struct ether_addr))
	{
		devlog(dev, LOG_ERR, "Short Reserve/Release request on %s", q->iface->name);
		return finish_request(q, AOE_ERR_BADARG);
	}

	++q->dev->stats.other_req;

	switch (q->reserve_hdr.rcmd)
	{
		case AOE_RESERVE_READ:
			break;
		case AOE_RESERVE_SET:
			if (dev->reserve->length &&
					!match_acl(dev->reserve, &q->aoe_hdr.addr))
				return finish_request(q, AOE_ERR_RESERVED);
			/* Fall through */
		case AOE_RESERVE_FORCESET:
			for (i = 0; i < q->reserve_hdr.nmacs; i++)
				memcpy(&dev->reserve->entries[i], &addrs[i], ETH_ALEN);
			dev->reserve->length = i;
			msync(dev->reserve, sizeof(*dev->reserve), MS_ASYNC);
			break;
		default:
			devlog(dev, LOG_ERR, "Unknown Reserve/Release subcommand %d",
				q->reserve_hdr.rcmd);
			return finish_request(q, AOE_ERR_BADARG);
	}

	for (i = 0; i < dev->reserve->length; i++)
		memcpy(&addrs[i], &dev->reserve->entries[i], ETH_ALEN);
	q->reserve_hdr.nmacs = i;
	q->length = i * sizeof(struct ether_addr);

	return finish_request(q, 0);
}

void process_request(struct netif *iface, struct device *dev, void *buf,
	int len, const struct timespec *tv)
{
	const struct aoe_hdr *pkt = buf;
	struct queue_item *q;

	/* Check the ACLs */
	if (dev->cfg.accept && !match_acl(dev->cfg.accept, &pkt->addr.ether_shost))
		return;
	if (dev->cfg.deny && match_acl(dev->cfg.deny, &pkt->addr.ether_shost))
		return;
	/* Check the dynamic MAC mask list */
	if (dev->mac_mask->length && !match_acl(dev->mac_mask, &pkt->addr.ether_shost))
		return;

	/* If the queue is full, try to flush completed things out. If that
	 * fails, just drop the request */
	q = queue_get(dev, iface, buf, len, tv);
	if (G_UNLIKELY(!q))
	{
		run_queue(dev);
		q = queue_get(dev, iface, buf, len, tv);
	}
	if (G_UNLIKELY(!q))
	{
		devlog(dev, LOG_NOTICE, "Queue full, dropping request (deferred: %d)",
			dev->deferred->len);
		++dev->stats.queue_full;
		return;
	}

	if (pkt->cmd > sizeof(aoe_cmds) / sizeof(aoe_cmds[0]) ||
			!aoe_cmds[pkt->cmd].header_length)
	{
		/* Do not warn for vendor-specific commands */
		if (pkt->cmd < AOE_CMD_VENDOR)
			devlog(dev, LOG_ERR, "Unknown AoE command 0x%02x", pkt->cmd);
		memcpy(&q->aoe_hdr, pkt, sizeof(struct aoe_hdr));
		q->hdrlen = sizeof(struct aoe_hdr);
		return finish_request(q, AOE_ERR_BADCMD);
	}

	if (G_UNLIKELY(q->length < aoe_cmds[pkt->cmd].header_length))
	{
		devlog(dev, LOG_ERR, "Short request on %s", q->iface->name);
		return finish_request(q, AOE_ERR_BADCMD);
	}

	memcpy(&q->ata_hdr, q->buf, aoe_cmds[pkt->cmd].header_length);
	q->hdrlen = aoe_cmds[pkt->cmd].header_length;

	if (clone_pkt(q))
		return drop_request(q);

	if (G_UNLIKELY(dev->cfg.trace_io))
		aoe_cmds[pkt->cmd].trace(dev, q);

	aoe_cmds[pkt->cmd].process(dev, q);
}

static void send_fake_cfg_rsp(struct device *dev, struct netif *iface,
	const struct ether_addr *dst)
{
	struct queue_item *q;

	/* Do not consider the device's normal queue length here */
	q = new_request(dev, iface, NULL, 0, NULL);

	/* finish_request() will swap the addresses */
	memcpy(&q->cfg_hdr.aoehdr.addr.ether_shost, dst, ETH_ALEN);
	memcpy(&q->cfg_hdr.aoehdr.addr.ether_dhost, &iface->mac, ETH_ALEN);
	q->cfg_hdr.aoehdr.addr.ether_type = htons(ETH_P_AOE);

	q->cfg_hdr.aoehdr.version = AOE_VERSION;
	q->cfg_hdr.aoehdr.shelf = dev->cfg.shelf;
	q->cfg_hdr.aoehdr.slot = dev->cfg.slot;
	q->cfg_hdr.aoehdr.cmd = AOE_CMD_CFG;

	q->cfg_hdr.ccmd = AOE_CFG_READ;
	q->hdrlen = sizeof(q->cfg_hdr);

	do_cfg_cmd(dev, q);
}

static void send_advertisment(struct device *dev, struct netif *iface)
{
	struct ether_addr mac;
	unsigned i;

	if (!dev->cfg.accept || !dev->cfg.accept->length || dev->cfg.broadcast)
	{
		/* If there is no accept list, send a broadcast */
		memset(&mac, 0xff, sizeof(mac));
		send_fake_cfg_rsp(dev, iface, &mac);
	}
	else
	{
		/* Enqueue an advertisement for every allowed host */
		for (i = 0; i < dev->cfg.accept->length; i++)
		{
			struct ether_addr dst;

			memcpy(&dst, &dev->cfg.accept->entries[i], ETH_ALEN);
			send_fake_cfg_rsp(dev, iface, &dst);
		}
	}
	run_queue(dev);
}

void attach_device(void *data, void *user_data)
{
	struct device *dev = data;
	struct netif *iface = user_data;
	unsigned j;

	if (dev->cfg.iface_patterns && !match_patternlist(dev->cfg.iface_patterns, iface->name))
		return;

	/* Check if the device is already attached */
	for (j = 0; j < iface->devices->len; j++)
		if (dev == g_ptr_array_index(iface->devices, j))
			return;

	g_ptr_array_add(iface->devices, dev);
	g_ptr_array_add(dev->ifaces, iface);

	send_advertisment(dev, iface);
}

void detach_device(struct netif *iface, struct device *dev)
{
	struct submit_slot *s;
	struct queue_item *q;
	GList *l;
	unsigned i;

	for (l = dev->active.head; l; l = l->next)
	{
		s = l->data;
		for (i = 0; i < s->num_iov; i++)
			if (s->items[i]->iface == iface)
				s->items[i]->iface = NULL;
	}
	for (i = 0; i < dev->deferred->len; i++)
	{
		q = g_ptr_array_index(dev->deferred, i);
		if (q->iface == iface)
			q->iface = NULL;
	}
	for (i = 0; i < iface->deferred->len; i++)
	{
		q = g_ptr_array_index(iface->deferred, i);
		if (q->dev == dev)
		{
			q->dev = NULL;
			--dev->queue_length;
		}
	}

	g_ptr_array_remove(iface->devices, dev);
	g_ptr_array_remove(dev->ifaces, iface);
}

static void invalidate_device(struct device *dev)
{
	struct io_event ev;
	unsigned i;
	GList *l;

	devlog(dev, LOG_DEBUG, "Shutting down");

	for (i = 0; i < dev->deferred->len; i++)
		drop_request(g_ptr_array_index(dev->deferred, i));
	if (dev->deferred->len)
		g_ptr_array_remove_range(dev->deferred, 0, dev->deferred->len);

	while ((l = g_queue_pop_head_link(&dev->active)))
	{
		struct submit_slot *s = l->data;
		unsigned i;

		io_cancel(dev->aio_ctx, &s->iocb, &ev);
		for (i = 0; i < s->num_iov; i++)
			drop_request(s->items[i]);
		g_slice_free(struct submit_slot, s);
	}

	while (dev->ifaces->len)
		detach_device(g_ptr_array_index(dev->ifaces, 0), dev);

	deactivate_dev(dev);
	g_ptr_array_remove(devices, dev);
	free_dev(dev);
}

void setup_devices(void)
{
	struct device *dev;
	char **groups;
	unsigned i, j;

	if (!devices)
		devices = g_ptr_array_new();

	/* Look for devices that are no longer needed or should be re-opened */
	for (i = 0; i < devices->len;)
	{
		dev = g_ptr_array_index(devices, i);
		if (!g_key_file_has_group(global_config, dev->name) || reopen_needed(dev))
			invalidate_device(dev);
		else
			i++;
	}

	/* Look for new devices and refresh the configuration of existing ones */
	groups = g_key_file_get_groups(global_config, NULL);
	for (i = 0; groups[i]; i++)
	{
		/* Skip special groups */
		if (!strcmp(groups[i], "defaults") || !strcmp(groups[i], "acls"))
			continue;

		if (!g_key_file_has_key(global_config, groups[i], "shelf", NULL))
			continue;

		/* Check if a device with the same name already exists */
		for (j = 0; j < devices->len; j++)
		{
			dev = g_ptr_array_index(devices, j);
			if (!strcmp(groups[i], dev->name))
				break;
		}

		/* If not, allocate a new one */
		if (j >= devices->len)
		{
			dev = alloc_dev(groups[i]);
			if (!dev)
				continue;
			g_ptr_array_add(devices, dev);
		}
		setup_dev(dev);
	}
	g_strfreev(groups);

	if (!devices->len)
	{
		logit(LOG_ERR, "No valid devices defined, shutting down");
		exit_flag = 1;
	}
}

void done_devices(void)
{
	while (devices->len)
		invalidate_device(g_ptr_array_index(devices, 0));
	g_ptr_array_free(devices, TRUE);
}
