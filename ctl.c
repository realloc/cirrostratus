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
	struct event_ctx	event_ctx;
	int			fd;
};

/**********************************************************************
 * Global variables
 */

/* Event context used for accepting new connections */
static struct event_ctx accept_ctx;

/* Socket descriptor for accepting new connections */
static int accept_fd = -1;

/* Location of the control socket */
static char *sockpath;

static void ctl_io(uint32_t events, void *data);

/**********************************************************************
 * Functions
 */

static struct ctl_ctx *alloc_ctl(int fd)
{
	struct ctl_ctx *ctx;

	ctx = g_new0(struct ctl_ctx, 1);
	ctx->fd = fd;
	ctx->event_ctx.callback = ctl_io;
	return ctx;
}

static void free_ctl(struct ctl_ctx *ctx)
{
	del_fd(ctx->fd);
	close(ctx->fd);
	g_free(ctx);
}

static void report_dev_stats(int fd)
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

static void report_net_stats(int fd)
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

static void ctl_io(uint32_t events, void *data)
{
	struct ctl_ctx *ctx = data;
	uint32_t cmd;
	ssize_t ret;

	if (events & (EPOLLHUP | EPOLLERR))
	{
		free_ctl(ctx);
		return;
	}

	ret = read(ctx->fd, &cmd, sizeof(cmd));
	if (ret < 0)
	{
		logerr("Ctl: read error");
		free_ctl(ctx);
		return;
	}
	if (ret != sizeof(cmd))
	{
		logit(LOG_ERR, "Ctl: short read");
		free_ctl(ctx);
		return;
	}

	switch (cmd)
	{
		case CTL_CMD_GET_STATS:
			/* XXX This is blocking I/O */
			report_dev_stats(ctx->fd);
			report_net_stats(ctx->fd);
			break;
		case CTL_CMD_RELOAD:
			reload_flag = 1;
			cmd = 0;
			write(ctx->fd, &cmd, sizeof(cmd));
			break;
		default:
			logit(LOG_ERR, "Ctl: unknown command");
			free_ctl(ctx);
			break;
	}
}

static void ctl_accept(uint32_t events, void *data G_GNUC_UNUSED)
{
	struct sockaddr_un sa;
	struct ctl_ctx *ctl;
	socklen_t salen;
	int val, ret;

	salen = sizeof(sa);
	ret = accept(accept_fd, (struct sockaddr *)&sa, &salen);
	if (ret == -1)
	{
		logerr("Ctl: accept() failed");
		ctl_done();
		return;
	}

	ctl = alloc_ctl(ret);
	add_fd(ctl->fd, &ctl->event_ctx);

	val = 64 * 1024;
	ret = setsockopt(ctl->fd, SOL_SOCKET, SO_SNDBUFFORCE, &val, sizeof(val));
	if (ret)
		setsockopt(ctl->fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
	if (ret)
		logerr("Ctl: Setting the send buffer size failed");
}

void ctl_init(void)
{
	struct sockaddr_un sa;
	mode_t oldmask;
	int ret;

	/* The configuration may change, so save the original value */
	sockpath = g_strdup(defaults.ctl_socket);

	unlink(sockpath);
	accept_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (accept_fd == -1)
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
	ret = bind(accept_fd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret)
	{
		logerr("Ctl: bind('%s') failed", sockpath);
		umask(oldmask);
		ctl_done();
		return;
	}
	umask(oldmask);

	ret = listen(accept_fd, 10);
	if (ret)
	{
		logerr("Ctl: listen() failed");
		ctl_done();
		return;
	}

	accept_ctx.callback = ctl_accept;
	add_fd(accept_fd, &accept_ctx);
}

void ctl_done(void)
{
	if (accept_fd != -1)
	{
		del_fd(accept_fd);
		close(accept_fd);
		accept_fd = -1;
	}
	if (sockpath)
	{
		unlink(sockpath);
		g_free(sockpath);
		sockpath = NULL;
	}
}
