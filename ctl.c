#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
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

	hello.type = CTL_MSG_HELLO;
	hello.version = CTL_PROTO_VERSION;

	sendto(ctl_fd, &hello, sizeof(hello), 0, (struct sockaddr *)&ctx->src, ctx->srclen);
}

static void send_uptime(const struct ctl_ctx *ctx)
{
	struct msg_uptime uptime;
	struct timespec now;

	uptime.type = CTL_MSG_UPTIME;

	clock_gettime(CLOCK_REALTIME, &now);
	uptime.uptime_sec = now.tv_sec - startup.tv_sec;
	uptime.uptime_nsec = now.tv_nsec - startup.tv_nsec;
	if (uptime.uptime_nsec < 0)
	{
		uptime.uptime_nsec += 1000000000;
		--uptime.uptime_sec;
	}

	sendto(ctl_fd, &uptime, sizeof(uptime), 0, (struct sockaddr *)&ctx->src, ctx->srclen);
}

static void send_dev_stat(const struct ctl_ctx *ctx, const struct device *dev)
{
	struct msg_devstat *stat;
	int len;

	len = sizeof(*stat) + strlen(dev->name) + 1;
	stat = g_malloc(len);
	stat->type = CTL_MSG_DEVSTAT;
	stat->stats = dev->stats;
	memcpy(&stat->name, dev->name, strlen(dev->name) + 1);
	sendto(ctl_fd, stat, len, 0, (struct sockaddr *)&ctx->src, ctx->srclen);
	g_free(stat);
}

static void send_net_stat(const struct ctl_ctx *ctx, const struct netif *iface)
{
	struct msg_netstat *stat;
	int len;

	len = sizeof(*stat) + strlen(iface->name) + 1;
	stat = g_malloc(len);
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

static void do_stats(const struct ctl_ctx *ctx, const GPtrArray *patterns)
{
	unsigned i;

	send_uptime(ctx);

	for (i = 0; i < devices->len; i++)
	{
		struct device *dev = g_ptr_array_index(devices, i);

		if (patterns && ! match_patternlist(patterns, dev->name))
			continue;
		send_dev_stat(ctx, dev);
	}
	for (i = 0; i < ifaces->len; i++)
	{
		struct netif *iface = g_ptr_array_index(ifaces, i);

		if (patterns && ! match_patternlist(patterns, iface->name))
			continue;
		send_net_stat(ctx, iface);
	}
	return send_msg_ok(ctx);
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

static void ctl_io(uint32_t events, void *data)
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

	switch (ctx->cmd)
	{
		case CTL_CMD_HELLO:
			send_hello(ctx);
			break;
		case CTL_CMD_GET_STATS:
			patterns = get_pattern_list(ctx->buf, ret);
			do_stats(ctx, patterns);
			break;
		case CTL_CMD_RELOAD:
			reload_flag = 1;
			send_msg_ok(ctx);
			break;
		default:
			logit(LOG_ERR, "Ctl: unknown command");
			break;
	}
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
