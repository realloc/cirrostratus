#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <sys/types.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <libaio.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#define EVENT_BATCH		16

/**********************************************************************
 * Forward declarations
 */

static void dev_io(uint32_t events, void *data);
static int send_response(struct queue_item *q, int sync);

/**********************************************************************
 * Global variables
 */

/* List of all configured devices */
static GPtrArray *devices;

#define ATACMD(x) [WIN_ ## x] = #x
static const char *ata_cmds[256] =
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
static const char *cfg_cmds[16] =
{
	CFGCMD(READ),
	CFGCMD(TEST),
	CFGCMD(TEST_PREFIX),
	CFGCMD(SET),
	CFGCMD(FORCE_SET)
};

/**********************************************************************
 * Misc. helpers
 */

static struct queue_item *queue_get(struct device *dev, struct netif *iface,
	void *buf, unsigned length, struct timeval *tv)
{
	struct queue_item *q;

	if (dev->q_tail - dev->q_head >= (unsigned)dev->cfg.queue_length)
		return NULL;

	dev->stats.queue_len += dev->q_tail - dev->q_head;

	q = dev->queue[dev->q_tail++ & dev->q_mask];
	q->iface = iface;
	q->buf = buf;
	q->bufsize = iface->mtu;
	q->length = length;

	if (tv)
		q->start = *tv;
	else
		gettimeofday(&q->start, NULL);

	return q;
}

static inline unsigned max_sect_nr(struct netif *iface)
{
	return (iface->mtu - sizeof(struct aoe_ata_hdr)) >> 9;
}

/**********************************************************************
 * Allocate/deallocate devices
 */

static void free_dev(struct device *dev)
{
	int i;

	g_free(dev->name);
	if (dev->fd != -1)
		close(dev->fd);
	if (dev->event_fd != -1)
	{
		del_fd(dev->event_fd);
		close(dev->event_fd);
	}
	if (dev->queue)
	{
		for (i = 0; i < dev->cfg.queue_length; i++)
			g_slice_free(struct queue_item, dev->queue[i]);
		g_free(dev->queue);
	}
	g_ptr_array_free(dev->ifaces, TRUE);
	destroy_device_config(&dev->cfg);
	g_slice_free(struct device, dev);
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
	dev->ifaces = g_ptr_array_new();
	dev->event_ctx.callback = dev_io;

	if (!get_device_config(name, &dev->cfg))
	{
		free_dev(dev);
		return NULL;
	}

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

	dev->event_fd = eventfd(0, 0);
	if (dev->event_fd == -1)
	{
		deverr(dev, "eventfd allocation failed");
		free_dev(dev);
		return NULL;
	}
	if (fcntl(dev->event_fd, F_SETFL, fcntl(dev->event_fd, F_GETFL) | O_NONBLOCK))
		deverr(dev, "Setting the eventfd to non-blocking mode have failed");

	add_fd(dev->event_fd, &dev->event_ctx);

	dev->q_mask = dev->cfg.queue_length - 1;
	dev->queue = g_new0(struct queue_item *, dev->cfg.queue_length);
	for (i = 0; i < (unsigned)dev->cfg.queue_length; i++)
	{
		dev->queue[i] = g_slice_new0(struct queue_item);
		dev->queue[i]->dev = dev;
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

	hsize = human_format(dev->size, &unit);
	devlog(dev, LOG_INFO, "Shelf %d, slot %d, path '%s' (size %lld %s, sectors %lld) opened%s%s",
		dev->cfg.shelf, dev->cfg.slot, dev->cfg.path, hsize, unit,
		(long long)dev->size >> 9,
		dev->cfg.read_only ? " R/O" : "",
		dev->cfg.direct_io ? ", using direct I/O" : "");

	return dev;
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

	/* Check compatibility of old and new fields */
	if (dev->cfg.path && strcmp(dev->cfg.path, newcfg.path))
	{
		deverr(dev, "The path cannot be changed on reload");
		g_free(newcfg.path);
		newcfg.path = g_strdup(dev->cfg.path);
	}
	if (dev->cfg.queue_length != newcfg.queue_length)
	{
		deverr(dev, "The queue length cannot be changed on reload");
		newcfg.queue_length = dev->cfg.queue_length;
	}
	if (dev->cfg.read_only != newcfg.read_only)
	{
		deverr(dev, "Read-only mode cannot be changed on reload");
		newcfg.read_only = dev->cfg.read_only;
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

	if (dev->cfg.direct_io != newcfg.direct_io)
	{
		long flags = fcntl(dev->fd, F_GETFL);
		if (newcfg.direct_io)
			flags |= O_DIRECT;
		else
			flags &= ~O_DIRECT;
		if (fcntl(dev->fd, F_SETFL, flags))
			deverr(dev, "Failed to change direct I/O settings");
		else
			devlog(dev, LOG_INFO, "%s direct I/O from now on",
				newcfg.direct_io ? "Using" : "Not using");
	}
}

/**********************************************************************
 * I/O handling
 */

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

/* Called when a request has been finished and a reply should be sent */
static void finish_request(struct queue_item *q, int error)
{
	struct timeval now, len, tmp;

	gettimeofday(&now, NULL);
	timersub(&now, &q->start, &len);
	timeradd(&q->dev->stats.req_time, &len, &tmp);
	q->dev->stats.req_time = tmp;

	if (error)
	{
		q->hdrlen = sizeof(struct aoe_hdr);
		q->aoe_hdr.is_error = TRUE;
		drop_buffer(q);
		++q->dev->stats.proto_err;
	}
	q->aoe_hdr.error = error;

	if (G_UNLIKELY(q->dev->cfg.trace_io))
		devlog(q->dev, LOG_DEBUG, "%s/%08x: Completed, status %d, time %d.%06ld",
			ether_ntoa((struct ether_addr *)&q->aoe_hdr.addr.ether_shost),
			(uint32_t)ntohl(q->aoe_hdr.tag), error,
			(int)len.tv_sec, len.tv_usec);

	/* Swap the source/destination addresses */
	memcpy(&q->aoe_hdr.addr.ether_dhost, &q->aoe_hdr.addr.ether_shost, ETH_ALEN);
	memcpy(&q->aoe_hdr.addr.ether_shost, &q->iface->mac, ETH_ALEN);

	/* Always supply our own shelf/slot address in case the request was a broadcast */
	q->aoe_hdr.shelf = htons(q->dev->cfg.shelf);
	q->aoe_hdr.slot = q->dev->cfg.slot;

	/* Mark the packet as a response */
	q->aoe_hdr.is_response = TRUE;

	q->state = READY;
	send_response(q, 0);
}

/* Drop a request without sending a reply */
static inline void drop_request(struct queue_item *q)
{
	drop_buffer(q);
	q->state = EMPTY;
	q->hdrlen = 0;
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
static void io_complete(struct queue_item *q, long res)
{
	if (res < 0)
	{
		devlog(q->dev, LOG_ERR, "%s request failed: %s",
			q->iocb.aio_lio_opcode == IO_CMD_PREAD ? "Read" : "Write",
			strerror(-res));
		return finish_ata(q, res == -EIO ? ATA_UNC : ATA_ABORTED,
			ATA_ERR | ATA_DRDY);
	}

	if (q->iocb.aio_lio_opcode == IO_CMD_PREAD)
		q->length = res;
	else
		q->length = 0;
	finish_ata(q, 0, ATA_DRDY);
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

	while (dev->submitted)
	{
		ret = io_getevents(dev->aio_ctx, 0, EVENT_BATCH, ev, NULL);
		if (ret < 0)
		{
			devlog(dev, LOG_ERR, "io_getevents() failed: %s",
				strerror(-ret));
			break;
		}

		for (i = 0; i < ret; i++)
			io_complete(ev[i].data, ev[i].res);
		dev->submitted -= ret;

		if (ret < EVENT_BATCH)
			break;
		else
			++dev->stats.dev_io_max_hit;
	}

	/* Try to submit pending I/Os */
	run_queue(dev, 0);
}

static int send_response(struct queue_item *q, int sync)
{
	static char zeroes[ETH_ZLEN];
	struct iovec iov[3];
	struct msghdr msg;
	unsigned len;
	int ret;

	if (!q->iface || q->iface->fd == -1)
	{
		drop_request(q);
		return 0;
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

	ret = sendmsg(q->iface->fd, &msg, sync ? 0 : MSG_DONTWAIT);
	if (ret != -1)
	{
		if (q->dev->congested)
			q->dev->congested = FALSE;
		q->iface->stats.tx_bytes += ret;
		++q->iface->stats.tx_cnt;
		drop_request(q);
		return 0;
	}

	if (errno == EAGAIN)
	{
		q->dev->congested = TRUE;
		if (!q->iface->congested)
		{
			modify_fd(q->iface->fd, &q->iface->event_ctx, EPOLLIN | EPOLLOUT);
			q->iface->congested = TRUE;
		}
	}
	else
		neterr(q->iface, "Write error");
	return -1;
}

static void submit(struct queue_item *q)
{
	struct iocb *iocbs[1];
	int ret;

	if (q->dev->io_stall)
	{
		q->state = PENDING;
		return;
	}

	iocbs[0] = &q->iocb;
	ret = io_submit(q->dev->aio_ctx, 1, iocbs);
	if (ret < 0)
	{
		if (ret == -EAGAIN)
		{
			q->state = PENDING;
			q->dev->io_stall = TRUE;
			++q->dev->stats.queue_stall;
			return;
		}
		devlog(q->dev, LOG_ERR, "Failed to submit I/O: %s", strerror(-ret));
		return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
	}

	q->dev->submitted++;
	q->state = SUBMITTED;
}

/* If sync is set, then _some_ progress must be made */
void run_queue(struct device *dev, int sync)
{
	struct queue_item *q;
	unsigned i, j, need_compress = 0;

	/* Submit any prepared I/Os */
	if (dev->io_stall)
	{
		dev->io_stall = FALSE;
		for (i = dev->q_head; i != dev->q_tail; i++)
		{
			q = dev->queue[i & dev->q_mask];
			if (q->state != PENDING)
				continue;
			submit(q);
			if (dev->io_stall)
				break;
		}
	}

	/* Send back the completed results */
	for (i = dev->q_head; i != dev->q_tail; i++)
	{
		q = dev->queue[i & dev->q_mask];

		switch (q->state)
		{
			case EMPTY:
				goto next;
			case PENDING:
			case SUBMITTED:
				continue;
			case READY:
				break;
			case FLUSH:
				/* The flush is complete if there are no more
				 * commands before it in the queue */
				if (i != dev->q_head)
					continue;
				q->state = READY;
				break;
		}

		if (send_response(q, sync))
			break;
next:
		if (i == dev->q_head)
			dev->q_head++;
		else
			need_compress = 1;
	}

	/* We only have to compress the queue if there are no more free entries
	 * at the end */
	if (!need_compress || dev->q_tail - dev->q_head !=
			(unsigned)dev->cfg.queue_length)
		return;

	/* Queue compression: move EMPTY slots past non-empty ones */
	i = j = dev->q_head;
	while (i != dev->q_tail)
	{
		q = dev->queue[i & dev->q_mask];
		if (q->state == EMPTY)
		{
			i++;
			continue;
		}
		/* Swap the empty entry with the non-empty one */
		if (i != j)
		{
			dev->queue[i & dev->q_mask] = dev->queue[j & dev->q_mask];
			dev->queue[j & dev->q_mask] = q;
		}
		j++;
		i++;
	}

	++dev->stats.compress_run;
	dev->stats.compress_entries += dev->q_tail - j;

	dev->q_tail = j;
}

static void ata_rw(struct queue_item *q, unsigned long long offset, int opcode)
{
	void *pkt;

	/* Allocate a new packet for the data that remains alive till the I/O
	 * completes and is also properly aligned for direct I/O */
	pkt = alloc_packet(q->bufsize);
	if (!pkt)
		return;
	memcpy(pkt, q->buf + q->hdrlen, q->length - q->hdrlen);
	q->length -= q->hdrlen;
	q->buf = pkt;
	q->dynalloc = TRUE;

	if (G_UNLIKELY(q->ata_hdr.nsect > max_sect_nr(q->iface)))
	{
		devlog(q->dev, LOG_ERR, "Request too large (%d)", q->ata_hdr.nsect);
		return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
	}
	if (G_UNLIKELY(opcode == IO_CMD_PWRITE &&
			q->length < (unsigned)q->ata_hdr.nsect << 9))
	{
		devlog(q->dev, LOG_ERR, "Short write request (have %u, requested %u)",
			q->length, (unsigned)q->ata_hdr.nsect << 9);
		return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
	}

	q->length = (unsigned)q->ata_hdr.nsect << 9;

	if (G_UNLIKELY(offset + q->length > q->dev->size))
	{
		devlog(q->dev, LOG_NOTICE, "Attempt to access beyond end-of-device");
		return finish_ata(q, ATA_IDNF, ATA_DRDY | ATA_ERR);
	}

	if (opcode == IO_CMD_PREAD)
	{
		io_prep_pread(&q->iocb, q->dev->fd, q->buf, q->length, offset);
		q->dev->stats.read_bytes += q->length;
		++q->dev->stats.read_req;
	}
	else
	{
		io_prep_pwrite(&q->iocb, q->dev->fd, q->buf, q->length, offset);
		q->dev->stats.write_bytes += q->length;
		++q->dev->stats.write_req;
	}
	q->iocb.data = q;
	io_set_eventfd(&q->iocb, q->dev->event_fd);

	submit(q);
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

	drop_buffer(q);
	q->buf = ident = alloc_packet(q->bufsize);
	if (!ident)
		return;
	memset(ident, 0, sizeof(*ident));
	q->dynalloc = TRUE;
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
	ident->command_set_2 = GUINT16_TO_LE((1 << 14) | (1 << 13) | (1 << 12) | (1 << 10));
	/* Bit 14: must be 1 */
	ident->cfsse = GUINT16_TO_LE(1 << 14);
	/* Bit 14: must be 1, bit 13: FLUSH_CACHE_EXT, bit 12: FLUSH_CACHE, bit 10: LBA48 */
	ident->cfs_enable_2 = GUINT16_TO_LE((1 << 14) | (1 << 13) | (1 << 12) | (1 << 10));
	/* Bit 14: must be 1 */
	ident->csf_default = GUINT16_TO_LE(1 << 14);
	/* Bit 14: must be 1, bit 3: device 0 passed diag, bit 2-1: 01 - jumper, bit 0: must be 1 */
	ident->hw_config = GUINT16_TO_LE(0x400b);

	ident->lba_capacity_2 = GUINT64_TO_LE(q->dev->size >> 9);

	q->ata_hdr.err_feature = 0;
	q->ata_hdr.cmdstat = ATA_DRDY;

	finish_request(q, 0);
}

static void trace_ata(const struct device *dev, const struct aoe_ata_hdr *pkt,
	unsigned long long lba)
{
	const char *cmd;
	char buf[16];

	cmd = ata_cmds[pkt->cmdstat];
	if (!cmd)
	{
		snprintf(buf, sizeof(buf), "Unknown (%02x)", pkt->cmdstat);
		cmd = buf;
	}

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
	unsigned i;

	if (q->length < sizeof(struct aoe_ata_hdr))
	{
		devlog(dev, LOG_ERR, "Short ATA request on %s", q->iface->name);
		return finish_request(q, AOE_ERR_BADCMD);
	}

	memcpy(&q->ata_hdr, q->buf, sizeof(struct aoe_ata_hdr));
	q->hdrlen = sizeof(struct aoe_ata_hdr);

	lba = 0;
	for (i = 0; i < 6; i++)
		lba |= q->ata_hdr.lba[i] << (i * 8);
	if (!q->ata_hdr.is_lba48)
		lba &= MAX_LBA28;

	if (G_UNLIKELY(dev->cfg.trace_io))
		trace_ata(dev, &q->ata_hdr, lba);

	switch (q->ata_hdr.cmdstat)
	{
		case WIN_READ:
		case WIN_READ_EXT:
			return ata_rw(q, lba << 9, IO_CMD_PREAD);
		case WIN_WRITE:
		case WIN_WRITE_EXT:
			if (q->dev->cfg.read_only)
				return finish_ata(q, ATA_ABORTED, ATA_DRDY | ATA_ERR);
			return ata_rw(q, lba << 9, IO_CMD_PWRITE);
		case WIN_IDENTIFY:
			return do_identify(q);
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
				run_queue(dev, 0);
			return;
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

static void trace_cfg(const struct device *dev, const struct aoe_cfg_hdr *pkt, char *cfg)
{
	const char *cmd;
	char buf[16];

	cmd = cfg_cmds[pkt->ccmd];
	if (!cmd)
	{
		snprintf(buf, sizeof(buf), "Unknown (%02x)", pkt->ccmd);
		cmd = buf;
	}

	if (pkt->ccmd == AOE_CFG_SET || pkt->ccmd == AOE_CFG_FORCE_SET)
		devlog(dev, LOG_DEBUG, "%s/%08x: Received CFG cmd %s (%.*s)",
			ether_ntoa((struct ether_addr *)&pkt->aoehdr.addr.ether_shost),
			(uint32_t)ntohl(pkt->aoehdr.tag), cmd,
			(int)ntohs(pkt->cfg_len), cfg);
	else
		devlog(dev, LOG_DEBUG, "%s/%08x: Received CFG cmd %s",
			ether_ntoa((struct ether_addr *)&pkt->aoehdr.addr.ether_shost),
			(uint32_t)ntohl(pkt->aoehdr.tag), cmd);
}

static void do_cfg_cmd(struct device *dev, struct queue_item *q)
{
	unsigned len;
	void *cfg;

	if (q->length < sizeof(q->cfg_hdr))
	{
		devlog(dev, LOG_ERR, "Short CFG request on %s", q->iface->name);
		return finish_request(q, AOE_ERR_BADCMD);
	}

	memcpy(&q->cfg_hdr, q->buf, sizeof(struct aoe_cfg_hdr));
	q->hdrlen = sizeof(struct aoe_cfg_hdr);
	cfg = q->buf + sizeof(struct aoe_cfg_hdr);

	len = ntohs(q->cfg_hdr.cfg_len);
	if (len > q->length - sizeof(struct aoe_cfg_hdr))
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
	if (G_UNLIKELY(dev->cfg.trace_io))
		trace_cfg(dev, &q->cfg_hdr, cfg);

	switch (q->cfg_hdr.ccmd)
	{
		case AOE_CFG_READ:
			break;
		case AOE_CFG_TEST:
			if (len != dev->aoe_conf_len)
				return drop_request(q);
			/* Fall through */
		case AOE_CFG_TEST_PREFIX:
			if (len > dev->aoe_conf_len || memcmp(cfg, dev->aoe_conf, len))
				return drop_request(q);
			break;
		case AOE_CFG_SET:
			if (dev->aoe_conf_len && (dev->aoe_conf_len != len ||
					memcmp(cfg, dev->aoe_conf, len)))
				return finish_request(q, AOE_ERR_CFG_SET);
			/* Fall through */
		case AOE_CFG_FORCE_SET:
			g_free(dev->aoe_conf);
			dev->aoe_conf = g_malloc(len);
			memcpy(dev->aoe_conf, cfg, len);
			dev->aoe_conf_len = len;
			break;
		default:
			return finish_request(q, AOE_ERR_BADARG);
	}

	q->cfg_hdr.queuelen = htons(dev->cfg.queue_length);
	q->cfg_hdr.firmware = 1;
	q->cfg_hdr.maxsect = max_sect_nr(q->iface);
	q->cfg_hdr.version = AOE_VERSION;

	len = dev->aoe_conf_len;
	q->cfg_hdr.cfg_len = htons(len);

	drop_buffer(q);
	if (len)
	{
		if (len > q->bufsize)
			len = q->bufsize;
		q->buf = dev->aoe_conf;
		q->length = len;
	}

	finish_request(q, 0);
}

void process_request(struct netif *iface, struct device *dev, void *buf, int len, struct timeval *tv)
{
	struct aoe_hdr *pkt = buf;
	struct queue_item *q;

	/* If the queue is full, try to flush completed things out. If that
	 * fails, just drop the request */
	q = queue_get(dev, iface, buf, len, tv);
	if (G_UNLIKELY(!q))
	{
		run_queue(dev, 0);
		q = queue_get(dev, iface, buf, len, tv);
	}
	if (G_UNLIKELY(!q))
	{
		devlog(dev, LOG_NOTICE, "Queue full, dropping request");
		++dev->stats.queue_full;
		return free_packet(buf, iface->mtu);
	}

	if (pkt->version != AOE_VERSION)
	{
		memcpy(&q->aoe_hdr, pkt, sizeof(struct aoe_hdr));
		q->hdrlen = sizeof(struct aoe_hdr);
		return finish_request(q, AOE_ERR_UNSUPVER);
	}

	switch (pkt->cmd)
	{
		case AOE_CMD_ATA:
			return do_ata_cmd(dev, q);
		case AOE_CMD_CFG:
			return do_cfg_cmd(dev, q);
		default:
			/* Do not warn for vendor-specific commands */
			if (pkt->cmd < AOE_CMD_VENDOR)
				devlog(dev, LOG_ERR, "Unknown AoE command 0x%02x", pkt->cmd);
			memcpy(&q->aoe_hdr, pkt, sizeof(struct aoe_hdr));
			q->hdrlen = sizeof(struct aoe_hdr);
			return finish_request(q, AOE_ERR_BADCMD);
	}
}

static void send_fake_cfg_rsp(struct device *dev, struct netif *iface,
	const struct ether_addr *dst)
{
	struct aoe_cfg_hdr *pkt;
	struct queue_item *q;

	pkt = alloc_packet(iface->mtu);
	if (!pkt)
		return;

	while (!(q = queue_get(dev, iface, pkt, sizeof(*pkt), NULL)))
		run_queue(dev, 1);
	q->dynalloc = TRUE;

	memset(pkt, 0, sizeof(*pkt));

	/* finish_request() will swap the addresses */
	memcpy(&pkt->aoehdr.addr.ether_shost, dst, ETH_ALEN);
	memcpy(&pkt->aoehdr.addr.ether_dhost, &iface->mac, ETH_ALEN);
	pkt->aoehdr.addr.ether_type = htons(ETH_P_AOE);

	pkt->aoehdr.version = AOE_VERSION;
	pkt->aoehdr.shelf = htons(dev->cfg.shelf);
	pkt->aoehdr.slot = dev->cfg.slot;
	pkt->aoehdr.cmd = AOE_CMD_CFG;

	pkt->ccmd = AOE_CFG_READ;

	do_cfg_cmd(dev, q);
}

static void send_advertisment(struct device *dev, struct netif *iface)
{
	struct ether_addr mac;
	unsigned i;

	if (!dev->cfg.accept || !dev->cfg.accept->len || dev->cfg.broadcast)
	{
		/* If there is no accept list, send a broadcast */
		memset(&mac, 0xff, sizeof(mac));
		send_fake_cfg_rsp(dev, iface, &mac);
	}
	else
	{
		/* Enqueue an advertisement for every allowed host */
		for (i = 0; i < dev->cfg.accept->len; i++)
			send_fake_cfg_rsp(dev, iface,
				&g_array_index(dev->cfg.accept, struct ether_addr, i));
	}
	run_queue(dev, 0);
}

void attach_devices(struct netif *iface)
{
	struct device *dev;
	unsigned i, j;

	for (i = 0; i < devices->len; i++)
	{
		dev = g_ptr_array_index(devices, i);
		if (dev->cfg.iface_patterns && !match_patternlist(dev->cfg.iface_patterns, iface->name))
			continue;

		/* Check if the device is already attached */
		for (j = 0; j < iface->devices->len; j++)
			if (dev == g_ptr_array_index(iface->devices, j))
				break;
		if (j < iface->devices->len)
			continue;

		g_ptr_array_add(iface->devices, dev);
		g_ptr_array_add(dev->ifaces, iface);

		send_advertisment(dev, iface);
	}
}

void detach_device(struct netif *iface, struct device *dev)
{
	struct queue_item *q;
	struct io_event ev;
	unsigned i;

	for (i = dev->q_head; i != dev->q_tail; i++)
	{
		q = dev->queue[i & dev->q_mask];
		if (q->iface != iface)
			continue;
		if (q->state == SUBMITTED)
		{
			if (!io_cancel(dev->aio_ctx, &q->iocb, &ev))
				dev->submitted--;
		}
		drop_request(q);
	}

	g_ptr_array_remove(iface->devices, dev);
	g_ptr_array_remove(dev->ifaces, iface);
}

static void drain_ios(struct device *dev)
{
	struct io_event ev[16];
	int ret, i;

	while (dev->submitted)
	{
		ret = io_getevents(dev->aio_ctx, 1, sizeof(ev) / sizeof(ev[0]), ev, NULL);
		if (ret < 0)
		{
			devlog(dev, LOG_ERR, "io_getevents() failed: %s",
				strerror(-ret));
			break;
		}

		for (i = 0; i < ret; i++)
			io_complete(ev[i].data, ev[i].res);
		dev->submitted -= ret;
	}
}

static void invalidate_device(struct device *dev)
{
	devlog(dev, LOG_DEBUG, "Shutting down");
	drain_ios(dev);
	while (dev->q_head != dev->q_tail)
		run_queue(dev, 1);
	while (dev->ifaces->len)
		detach_device(g_ptr_array_index(dev->ifaces, 0), dev);
	g_ptr_array_remove(devices, dev);
	free_dev(dev);
}

void report_dev_stats(int fd)
{
	uint32_t val, i;

	val = devices->len;
	write(fd, &val, sizeof(val));

	for (i = 0; i < devices->len; i++)
	{
		struct device *dev = g_ptr_array_index(devices, i);

		val = strlen(dev->name);
		write(fd, &val, sizeof(val));
		write(fd, dev->name, strlen(dev->name));
		val = sizeof(dev->stats);
		write(fd, &val, sizeof(val));
		write(fd, &dev->stats, sizeof(dev->stats));
	}
}

void setup_devices(void)
{
	struct device *dev;
	char **groups;
	unsigned i, j;

	if (!devices)
		devices = g_ptr_array_new();

	/* Look for devices that are no longer needed */
	for (i = 0; i < devices->len;)
	{
		dev = g_ptr_array_index(devices, i);
		if (!g_key_file_has_group(global_config, dev->name))
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
