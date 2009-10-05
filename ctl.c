#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"
#include "ctl.h"
#include "util.h"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <glib.h>

/**********************************************************************
 * Data structures
 */

/* Context for an accepted control connection */
struct ctl_ctx
{
	struct sockaddr_un	src;
	socklen_t		srclen;
	union
	{
		char		buf[CTL_MAX_PACKET];
		uint32_t	cmd;
	};
};

/**********************************************************************
 * Global variables
 */

/* Event context used for accepting new connections */
static struct event_ctx ctl_event;

/* Socket descriptor for accepting new connections */
static int ctl_fd = -1;

/* Location of the control socket */
static char *sockpath;

static void ctl_io(uint32_t events, void *data);

/**********************************************************************
 * Functions
 */

static void send_hello(const struct ctl_ctx *ctx)
{
	struct msg_hello hello;

	memset(&hello, 0, sizeof(hello));
	hello.type = CTL_MSG_HELLO;
	hello.version = CTL_PROTO_VERSION;

	sendto(ctl_fd, &hello, sizeof(hello), 0, (struct sockaddr *)&ctx->src, ctx->srclen);
}

static void send_uptime(const struct ctl_ctx *ctx)
{
	struct msg_uptime uptime;
	struct timespec now;

	memset(&uptime, 0, sizeof(uptime));
	uptime.type = CTL_MSG_UPTIME;

	clock_gettime(CLOCK_REALTIME, &now);
	timespec_sub(&now, &startup, &uptime.uptime);

	sendto(ctl_fd, &uptime, sizeof(uptime), 0, (struct sockaddr *)&ctx->src, ctx->srclen);
}

static void send_dev_stat(const struct ctl_ctx *ctx, struct device *dev)
{
	struct msg_devstat *stat;
	int len;

	len = sizeof(*stat) + strlen(dev->name) + 1;
	stat = g_malloc0(len);
	stat->type = CTL_MSG_DEVSTAT;
	stat->stats = dev->stats;
	memcpy(&stat->name, dev->name, strlen(dev->name) + 1);
	sendto(ctl_fd, stat, len, 0, (struct sockaddr *)&ctx->src, ctx->srclen);
	g_free(stat);
}

static void send_net_stat(const struct ctl_ctx *ctx, struct netif *iface)
{
	struct msg_netstat *stat;
	int len;

	len = sizeof(*stat) + strlen(iface->name) + 1;
	stat = g_malloc0(len);
	stat->type = CTL_MSG_NETSTAT;
	stat->stats = iface->stats;
	memcpy(&stat->name, iface->name, strlen(iface->name) + 1);
	sendto(ctl_fd, stat, len, 0, (struct sockaddr *)&ctx->src, ctx->srclen);
	g_free(stat);
}

static void send_msg_ok(const struct ctl_ctx *ctx)
{
	uint32_t type;

	type = CTL_MSG_OK;
	sendto(ctl_fd, &type, sizeof(type), 0, (struct sockaddr *)&ctx->src, ctx->srclen);
}

static void for_each_dev(const struct ctl_ctx *ctx, const GPtrArray *patterns,
	void (*fn)(const struct ctl_ctx *ctx, struct device *dev))
{
	unsigned i;

	for (i = 0; i < devices->len; i++)
	{
		struct device *dev = g_ptr_array_index(devices, i);

		if (patterns && !match_patternlist(patterns, dev->name))
			continue;
		fn(ctx, dev);
	}
}

static void for_each_iface(const struct ctl_ctx *ctx, const GPtrArray *patterns,
	void (*fn)(const struct ctl_ctx *ctx, struct netif *iface))
{
	unsigned i;

	for (i = 0; i < ifaces->len; i++)
	{
		struct netif *iface = g_ptr_array_index(ifaces, i);

		if (patterns && !match_patternlist(patterns, iface->name))
			continue;
		fn(ctx, iface);
	}
}

static void send_config(const struct ctl_ctx *ctx, struct device *dev)
{
	struct msg_config *res;
	int len;

	len = sizeof(*res) + strlen(dev->name) + 1;
	res = g_malloc0(len);

	res->type = CTL_MSG_CONFIG;
	res->cfg = *dev->aoe_conf;
	memcpy(&res->name, dev->name, strlen(dev->name) + 1);
	sendto(ctl_fd, res, len, 0, (struct sockaddr *)&ctx->src, ctx->srclen);
	g_free(res);
}

static void send_maclist(const struct ctl_ctx *ctx, struct device *dev)
{
	struct msg_maclist *res;
	int len;

	len = sizeof(*res) + strlen(dev->name) + 1;
	res = g_malloc0(len);

	res->type = CTL_MSG_MACLIST;
	switch (ctx->cmd)
	{
		case CTL_CMD_GET_MACMASK:
			res->list = *dev->mac_mask;
			break;
		case CTL_CMD_GET_RESERVE:
			res->list = *dev->mac_mask;
			break;
		default:
			logit(LOG_ERR, "Unknown MAC list requested");
			goto out;
	}

	memcpy(&res->name, dev->name, strlen(dev->name) + 1);
	sendto(ctl_fd, res, len, 0, (struct sockaddr *)&ctx->src, ctx->srclen);

out:
	g_free(res);
}

static void clear_dev_stat(const struct ctl_ctx *ctx, struct device *dev)
{
	memset(&dev->stats, 0, sizeof(dev->stats));
}

static void clear_net_stat(const struct ctl_ctx *ctx, struct netif *iface)
{
	memset(&iface->stats, 0, sizeof(iface->stats));
}

static void clear_config(const struct ctl_ctx *ctx, struct device *dev)
{
	dev->aoe_conf->length = 0;
	memset(&dev->aoe_conf->data, 0, sizeof(dev->aoe_conf->data));
	msync(dev->aoe_conf, sizeof(*dev->aoe_conf), MS_ASYNC);
}

static void clear_maclist(const struct ctl_ctx *ctx, struct device *dev)
{
	struct acl_map *map;

	switch (ctx->cmd)
	{
		case CTL_CMD_CLEAR_MACMASK:
			map = dev->mac_mask;
			break;
		case CTL_CMD_CLEAR_RESERVE:
			map = dev->reserve;
			break;
		default:
			logit(LOG_ERR, "Unknown MAC list clearing requested");
			return;
	}

	map->length = 0;
	memset(&map->entries, 0, sizeof(map->entries));
	msync(map, sizeof(*map), MS_ASYNC);
}

static GPtrArray *get_pattern_list(char *buf, int len)
{
	GPtrArray *list;
	char **strs;
	int i, cnt;

	/* Skip the command code */
	buf += 4;
	len -= 4;

	if (!len)
		return NULL;

	/* Count the number of strings */
	for (i = cnt = 0; i < len; i++)
		if (!buf[i])
			cnt++;

	strs = g_new(char *, cnt + 1);
	i = cnt = 0;
	while (i < len)
	{
		strs[cnt++] = buf;
		while (i < len && buf[i])
			++i;
		/* Skip the '\0' */
		++i;
	}
	strs[cnt] = NULL;

	list = g_ptr_array_new();
	build_patternlist(list, strs);
	g_free(strs);
	return list;
}

static void ctl_io(uint32_t events, void *data G_GNUC_UNUSED)
{
	GPtrArray *patterns;
	struct ctl_ctx *ctx;
	ssize_t ret;

	if (events & (EPOLLHUP | EPOLLERR))
	{
		logerr("Ctl: socket error");
		del_fd(ctl_fd);
		close(ctl_fd);
		return;
	}

	ctx = g_new(struct ctl_ctx, 1);

	ctx->srclen = sizeof(ctx->src);
	ret = recvfrom(ctl_fd, &ctx->buf, sizeof(ctx->buf), MSG_DONTWAIT,
		(struct sockaddr *)&ctx->src, &ctx->srclen);
	if (ret < 0)
	{
		if (errno != EAGAIN)
			logerr("Ctl: read error: %s", strerror(errno));
		g_free(ctx);
		return;
	}
	if (ret < (int)sizeof(ctx->cmd))
	{
		logit(LOG_ERR, "Ctl: short read");
		g_free(ctx);
		return;
	}

	patterns = NULL;

	switch (ctx->cmd)
	{
		case CTL_CMD_HELLO:
			send_hello(ctx);
			goto out;
		case CTL_CMD_GET_STATS:
			patterns = get_pattern_list(ctx->buf, ret);
			send_uptime(ctx);
			for_each_dev(ctx, patterns, send_dev_stat);
			for_each_iface(ctx, patterns, send_net_stat);
			break;
		case CTL_CMD_RELOAD:
			reload_flag = 1;
			break;
		case CTL_CMD_GET_CONFIG:
			patterns = get_pattern_list(ctx->buf, ret);
			for_each_dev(ctx, patterns, send_config);
			break;
		case CTL_CMD_GET_MACMASK:
		case CTL_CMD_GET_RESERVE:
			patterns = get_pattern_list(ctx->buf, ret);
			for_each_dev(ctx, patterns, send_maclist);
			break;
		case CTL_CMD_CLEAR_STATS:
			patterns = get_pattern_list(ctx->buf, ret);
			for_each_dev(ctx, patterns, clear_dev_stat);
			for_each_iface(ctx, patterns, clear_net_stat);
			break;
		case CTL_CMD_CLEAR_CONFIG:
			patterns = get_pattern_list(ctx->buf, ret);
			if (!patterns || !patterns->len)
				goto out;
			for_each_dev(ctx, patterns, clear_config);
			break;
		case CTL_CMD_CLEAR_MACMASK:
		case CTL_CMD_CLEAR_RESERVE:
			patterns = get_pattern_list(ctx->buf, ret);
			if (!patterns || !patterns->len)
				goto out;
			for_each_dev(ctx, patterns, clear_maclist);
			break;
		default:
			logit(LOG_ERR, "Ctl: Unknown command (%u)", ctx->cmd);
			break;
	}

	send_msg_ok(ctx);
out:
	free_patternlist(patterns);
	g_free(ctx);
}

void ctl_init(void)
{
	struct sockaddr_un sa;
	mode_t oldmask;
	int ret, val;

	/* The configuration may change, so save the original value */
	sockpath = g_strdup(defaults.ctl_socket);

	unlink(sockpath);
	ctl_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctl_fd == -1)
	{
		logerr("Ctl: socket() failed");
		g_free(sockpath);
		sockpath = NULL;
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sockpath);
	oldmask = umask(077);
	ret = bind(ctl_fd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret)
	{
		logerr("Ctl: bind('%s') failed", sockpath);
		umask(oldmask);
		ctl_done();
		return;
	}
	umask(oldmask);

	val = 64 * 1024;
	ret = setsockopt(ctl_fd, SOL_SOCKET, SO_SNDBUFFORCE, &val, sizeof(val));
	if (ret)
		setsockopt(ctl_fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
	if (ret)
		logerr("Ctl: Setting the send buffer size failed");

	ctl_event.callback = ctl_io;
	ctl_event.data = NULL;
	add_fd(ctl_fd, &ctl_event);
}

void ctl_done(void)
{
	if (ctl_fd != -1)
	{
		del_fd(ctl_fd);
		close(ctl_fd);
		ctl_fd = -1;
	}
	if (sockpath)
	{
		unlink(sockpath);
		g_free(sockpath);
		sockpath = NULL;
	}
}
