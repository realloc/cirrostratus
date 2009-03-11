#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include <blkid/blkid.h>

#define GRP_DEFAULTS		"defaults"
#define GRP_ACLS		"acls"

#define STATEDIR		LOCALSTATEDIR "/ggaoed"

/**********************************************************************
 * Global variables
 */

/* Do we have to finish? */
volatile int exit_flag;

/* Do we have to reload the configuration? */
volatile int reload_flag;

/* Parsed configuration file */
GKeyFile *global_config;

/* Configuration defaults */
struct default_config defaults;

/* epoll control file descriptor */
static int efd = -1;

/* If true, messages go to syslog, otherwise to stderr */
static int use_syslog;

/* Descriptor of the pid file */
static int pid_fd = -1;

/* Path of the pid file */
static char *pid_file;

/* If true, don't fork to the background */
static int nofork_flag;

/* If true, enable debug mode */
static int debug_flag;

/* libblkid cache for looking up devices by UUID */
static blkid_cache dev_cache;

/* Time the daemon has started at */
struct timespec startup;

/**********************************************************************
 * Generic helpers
 */

static void signal_handler(int sig)
{
	if (sig == SIGHUP)
		reload_flag = 1;
	else
		exit_flag = 1;
}

void logit(int level, const char *fmt, ...)
{
	va_list ap;
	char *msg;
	
	va_start(ap, fmt);
	if (use_syslog)
		vsyslog(level, fmt, ap);
	else
	{
		vasprintf(&msg, fmt, ap);
		printf("%s\n", msg);
		free(msg);
	}
	va_end(ap);
}

unsigned long long human_format(unsigned long long size, const char **unit)
{
	size >>= 10;
	*unit = "KiB";
	if (size >= 10240)
	{
		size >>= 10;
		*unit = "MiB";
	}
	if (size >= 10240)
	{
		size >>= 10;
		*unit = "GiB";
	}
	if (size >= 10240)
	{
		size >>= 10;
		*unit = "TiB";
	}
	return size;
}

/**********************************************************************
 * Event loop
 */

void add_fd(int fd, struct event_ctx *ctx)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = ctx;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
		logerr("Failed to watch fd");
}

void modify_fd(int fd, struct event_ctx *ctx, uint32_t events)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = events;
	event.data.ptr = ctx;
	if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event))
		logerr("EPOLL_CTL_MOD failed");
}

void del_fd(int fd)
{
	epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
}

static void event_init(void)
{
	efd = epoll_create(32);
	if (efd < 0)
	{
		logerr("Failed to create the epoll fd");
		exit_flag = 1;
	}
}

static void event_run(void)
{
	struct epoll_event events[16];
	struct event_ctx *ctx;
	int ret, i;

	while (!exit_flag && !reload_flag)
	{
		ret = epoll_wait(efd, events, sizeof(events) / sizeof(events[0]), 10000);
		if (ret == -1)
		{
			if (errno == EINTR)
				return;
			logerr("epoll_wait() failed");
			exit_flag = 1;
			return;
		}
		for (i = 0; i < ret; i++)
		{
			ctx = events[i].data.ptr;
			ctx->callback(events[i].events, ctx);
		}
		run_devices();
	}
}

/**********************************************************************
 * ACL management
 */

static struct acl *alloc_acl(const char *name)
{
	struct acl *acl;

	acl = g_slice_new0(struct acl);
	acl->name = g_strdup(name);

	return acl;
}

static void free_acl(struct acl *acl)
{
	g_free(acl->name);
	if (acl->map)
		g_slice_free(struct acl_map, acl->map);
	g_slice_free(struct acl, acl);
}

static struct acl *lookup_acl(const char *name)
{
	struct acl *acl;
	unsigned i;

	for (i = 0; i < defaults.acls->len; i++)
	{
		acl = g_ptr_array_index(defaults.acls, i);
		if (!strcmp(acl->name, name))
			return acl;
	}
	return NULL;
}

int add_one_acl(struct acl_map *acls, const struct ether_addr *addr)
{
	union padded_addr paddr;
	unsigned i;

	/* Ensure alignment */
	memset(&paddr, 0, sizeof(paddr));
	paddr.e = *addr;

	/* Don't add it twice */
	for (i = 0; i < acls->length; i++)
		if (acls->entries[i].u == paddr.u)
			return 0;

	if (acls->length >= sizeof(acls->entries) / sizeof(acls->entries[0]))
		return -1;

	acls->entries[acls->length++] = paddr;
	return 0;
}

void del_one_acl(struct acl_map *acls, const struct ether_addr *addr)
{
	union padded_addr paddr;
	unsigned i;

	/* Ensure alignment */
	memset(&paddr, 0, sizeof(paddr));
	paddr.e = *addr;

	for (i = 0; i < acls->length; i++)
		if (acls->entries[i].u == paddr.u)
			break;

	if (i >= acls->length)
		return;

	memmove(&acls->entries[i], &acls->entries[i + 1],
		sizeof(acls->entries[0]) * (acls->length - i - 1));
	--acls->length;
}

static int concat_acl(struct acl_map *dst, const struct acl *src)
{
	unsigned i;

	if (!src->map)
		return 0;

	for (i = 0; i < src->map->length; i++)
	{
		if (add_one_acl(dst, &src->map->entries[i].e))
			return -1;
	}
	return 0;
}

static void resolve_acls(struct acl_map **acls_out, char **values, const char *msgprefix)
{
	struct acl_map *acls;
	unsigned j;

	acls = g_slice_new0(struct acl_map);
	for (j = 0; values[j]; j++)
	{
		struct ether_addr addr;
		struct acl *ref;

		/* Try to parse the string as an ethernet MAC address first */
		if (ether_aton_r(values[j], &addr))
		{
			if (add_one_acl(acls, &addr))
			{
				logit(LOG_ERR, "%s: ACL table full", msgprefix);
				break;
			}
			continue;
		}

		/* Not a MAC address, maybe an already defined ACL */
		ref = lookup_acl(values[j]);
		if (ref)
		{
			if (concat_acl(acls, ref))
			{
				logit(LOG_ERR, "%s: ACL table full", msgprefix);
				break;
			}
			continue;
		}

		/* Still no success, try to look it up in /etc/ethers */
		if (!ether_hostton(values[j], &addr))
		{
			if (add_one_acl(acls, &addr))
			{
				logit(LOG_ERR, "%s: ACL table full", msgprefix);
				break;
			}
			continue;
		}

		logit(LOG_ERR, "%s: Failed to parse ACL element '%s'",
			msgprefix, values[j]);
	}

	if (acls->length)
		*acls_out = acls;
	else
	{
		g_slice_free(struct acl_map, acls);
		*acls_out = NULL;
	}
}

static int parse_acls(GKeyFile *config)
{
	char **keys, **values = NULL;
	struct acl *acl;
	GError *error;
	unsigned i;

	defaults.acls = g_ptr_array_new();

	keys = g_key_file_get_keys(config, GRP_ACLS, NULL, NULL);
	if (!keys)
		return TRUE;
	for (i = 0; keys[i]; i++)
	{
		acl = alloc_acl(keys[i]);

		error = NULL;
		values = g_key_file_get_string_list(config, GRP_ACLS, keys[i], NULL, &error);
		if (error)
		{
			logit(LOG_ERR, "Failed to parse ACL %s: %s", keys[i], error->message);
			g_error_free(error);
			goto error;
		}
		resolve_acls(&acl->map, values, keys[i]);
		g_ptr_array_add(defaults.acls, acl);
		g_strfreev(values);
	}
	g_strfreev(keys);
	return TRUE;

error:
	if (values)
		g_strfreev(values);
	free_acl(acl);
	g_strfreev(keys);
	return FALSE;
}

/* Match a MAC address against an ACL map */
int match_acl(const struct acl_map *acls, const void *mac)
{
	union padded_addr paddr;
	unsigned i;

	/* Ensure alignment */
	memset(&paddr, 0, sizeof(paddr));
	memcpy(&paddr.e, mac, ETH_ALEN);

	for (i = 0; i < acls->length; i++)
		if (acls->entries[i].u == paddr.u)
			return TRUE;
	return FALSE;
}

/**********************************************************************
 * Configuration handling
 */

int match_patternlist(const GPtrArray *list, const char *str)
{
	GPatternSpec *pattern;
	unsigned i;

	if (!list)
		return TRUE;

	for (i = 0; i < list->len; i++)
	{
		pattern = g_ptr_array_index(list, i);
		if (g_pattern_match_string(pattern, str))
			return TRUE;
	}
	return FALSE;
}

void build_patternlist(GPtrArray *list, char **elements)
{
	GPatternSpec *pattern;
	unsigned i;
	char *p;

	for (i = 0; elements[i]; i++)
	{
		p = elements[i];
		while (isspace(*p))
			p++;

		pattern = g_pattern_spec_new(p);
		g_ptr_array_add(list, pattern);
	}
}

static int parse_flag(GKeyFile *config, const char *section, const char *flag, int *val, int defval)
{
	GError *error = NULL;

	*val = g_key_file_get_boolean(config, section, flag, &error);
	if (!error)
		return TRUE;

	if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
	{
		logit(LOG_ERR, "%s: Failed to parse '%s': %s",
			section, flag, error->message);
		g_error_free(error);
		return FALSE;
	}
	*val = defval;
	g_error_free(error);
	return TRUE;
}

static int parse_int(GKeyFile *config, const char *section, const char *name, int *val, int defval)
{
	GError *error = NULL;

	*val = g_key_file_get_integer(config, section, name, &error);
	if (!error)
		return TRUE;

	if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
	{
		logit(LOG_ERR, "%s: Failed to parse '%s': %s",
			section, name, error->message);
		g_error_free(error);
		return FALSE;
	}
	*val = defval;
	g_error_free(error);
	return TRUE;
}

static void destroy_defaults(struct default_config *defcfg)
{
	if (defcfg->interfaces)
	{
		while (defcfg->interfaces->len)
		{
			g_pattern_spec_free(g_ptr_array_index(defcfg->interfaces, 0));
			g_ptr_array_remove_index_fast(defcfg->interfaces, 0);
		}
		g_ptr_array_free(defcfg->interfaces, TRUE);
	}

	if (defcfg->acls)
	{
		while (defcfg->acls->len)
		{
			free_acl(g_ptr_array_index(defcfg->acls, 0));
			g_ptr_array_remove_index_fast(defcfg->acls, 0);
		}
		g_ptr_array_free(defcfg->acls, TRUE);
	}

	g_free(defcfg->pid_file);
	g_free(defcfg->ctl_socket);
	g_free(defcfg->statedir);
}

static int queue_length_valid(unsigned len)
{
	return len >= MIN_QUEUE_LEN && len <= MAX_QUEUE_LEN;
}

static int parse_defaults(GKeyFile *config)
{
	char **patterns;
	int ret;

	if (!g_key_file_has_group(config, GRP_DEFAULTS))
		return TRUE;

	ret = parse_int(config, GRP_DEFAULTS, "queue-length", &defaults.queue_length, DEF_QUEUE_LEN);
	if (ret && !queue_length_valid(defaults.queue_length))
	{
		logit(LOG_ERR, "defaults: Invalid queue length");
		return FALSE;
	}
	ret &= parse_flag(config, GRP_DEFAULTS, "direct-io", &defaults.direct_io, TRUE);
	ret &= parse_flag(config, GRP_DEFAULTS, "trace-io", &defaults.trace_io, FALSE);

	/* The command line overrides the configuration */
	if (debug_flag)
		defaults.trace_io = TRUE;

	defaults.pid_file = g_key_file_get_string(config, GRP_DEFAULTS, "pid-file", NULL);
	if (!defaults.pid_file)
		defaults.pid_file = g_strdup(PIDFILE_LOCATION);
	defaults.ctl_socket = g_key_file_get_string(config, GRP_DEFAULTS, "control-socket", NULL);
	if (!defaults.ctl_socket)
		defaults.ctl_socket = g_strdup(SOCKET_LOCATION);
	defaults.statedir = g_key_file_get_string(config, GRP_DEFAULTS, "state-directory", NULL);
	if (!defaults.statedir)
		defaults.statedir = g_strdup(STATEDIR);

	ret &= parse_int(config, GRP_DEFAULTS, "mtu", &defaults.mtu, 0);
	if (ret && defaults.mtu && defaults.mtu < 1024 + (int)sizeof(struct aoe_cfg_hdr))
	{
		logit(LOG_ERR, "%s: Requested MTU is too small", GRP_DEFAULTS);
		return FALSE;
	}
	ret &= parse_int(config, GRP_DEFAULTS, "buffers", &defaults.buffers, DEF_BUFFERS);
	if (ret && (defaults.buffers < 0 || defaults.buffers > MAX_BUFFERS))
	{
		logit(LOG_ERR, "%s: Requested buffer count is invalid", GRP_DEFAULTS);
		return FALSE;
	}

	/* Compile the network interface pattern list */
	patterns = g_key_file_get_string_list(config, GRP_DEFAULTS, "interfaces", NULL, NULL);
	if (patterns)
	{
		defaults.interfaces = g_ptr_array_new();
		build_patternlist(defaults.interfaces, patterns);
		if (!defaults.interfaces->len)
		{
			g_ptr_array_free(defaults.interfaces, TRUE);
			defaults.interfaces = NULL;
		}
		g_strfreev(patterns);
	}

	return ret;
}

void destroy_device_config(struct device_config *devcfg)
{
	if (devcfg->iface_patterns)
	{
		while (devcfg->iface_patterns->len)
		{
			g_pattern_spec_free(g_ptr_array_index(devcfg->iface_patterns, 0));
			g_ptr_array_remove_index_fast(devcfg->iface_patterns, 0);
		}
		g_ptr_array_free(devcfg->iface_patterns, TRUE);
	}

	if (devcfg->accept)
		g_free(devcfg->accept);
	if (devcfg->deny)
		g_free(devcfg->deny);

	g_free(devcfg->path);
}

static int parse_device(GKeyFile *config, const char *name, struct device_config *devcfg)
{
	GError *error = NULL;
	char **vlist;
	int ret, val;

	memset(devcfg, 0, sizeof(*devcfg));

	ret = parse_flag(config, name, "direct-io", &devcfg->direct_io, defaults.direct_io);
	ret = parse_flag(config, name, "trace-io", &devcfg->trace_io, defaults.trace_io);
	ret &= parse_flag(config, name, "broadcast", &devcfg->broadcast, FALSE);
	ret &= parse_flag(config, name, "read-only", &devcfg->read_only, FALSE);

	ret &= parse_int(config, name, "queue-length", &val, defaults.queue_length);
	if (ret && !queue_length_valid(val))
	{
		logit(LOG_ERR, "%s: Invalid queue length", name);
		return FALSE;
	}
	devcfg->queue_length = val;

	ret &= parse_int(config, name, "shelf", &val, -1);
	if (ret && (val < 0 || val >= SHELF_BCAST))
	{
		logit(LOG_ERR, "%s: Missing or invalid shelf number", name);
		return FALSE;
	}
	devcfg->shelf = val;

	ret &= parse_int(config, name, "slot", &val, -1);
	if (ret && (val < 0 || val >= SLOT_BCAST))
	{
		logit(LOG_ERR, "%s: Missing or invalid slot number", name);
		return FALSE;
	}
	devcfg->slot = val;

	if (g_key_file_has_key(config, name, "uuid", NULL))
	{
		blkid_dev dev;
		char *uuid;

		if (g_key_file_has_key(config, name, "path", NULL))
		{
			logit(LOG_ERR, "%s: Only one of 'path' and 'uuid' "
				"may be specified", name);
			return FALSE;
		}

		uuid = g_key_file_get_string(config, name, "uuid", NULL);
		if (!dev_cache && blkid_get_cache(&dev_cache, NULL))
		{
			logit(LOG_ERR, "%s: UUID lookup failed: failed to "
				"initialize libblkid's cache", name);
			g_free(uuid);
			return FALSE;
		}

		dev = blkid_find_dev_with_tag(dev_cache, "UUID", uuid);
		g_free(uuid);
		if (!dev)
		{
			logit(LOG_ERR, "%s: UUID does not match any known device", name);
			return FALSE;
		}

		devcfg->path = g_strdup(blkid_dev_devname(dev));
	}
	else
	{
		devcfg->path = g_key_file_get_string(config, name, "path", &error);
		if (error)
		{
			logit(LOG_ERR, "%s: Failed to parse 'path': %s", name,
				error->message);
			g_error_free(error);
			return FALSE;
		}
	}

	/* Compile the network interface pattern list */
	vlist = g_key_file_get_string_list(config, name, "interfaces", NULL, NULL);
	if (vlist)
	{
		devcfg->iface_patterns = g_ptr_array_new();
		build_patternlist(devcfg->iface_patterns, vlist);
		g_strfreev(vlist);
		if (!devcfg->iface_patterns->len)
		{
			g_ptr_array_free(devcfg->iface_patterns, TRUE);
			devcfg->iface_patterns = NULL;
		}
	}

	/* Compile the access lists */
	vlist = g_key_file_get_string_list(config, name, "accept", NULL, NULL);
	if (vlist)
	{
		resolve_acls(&devcfg->accept, vlist, name);
		g_strfreev(vlist);
	}

	vlist = g_key_file_get_string_list(config, name, "deny", NULL, NULL);
	if (vlist)
	{
		resolve_acls(&devcfg->deny, vlist, name);
		g_strfreev(vlist);
	}
	return ret;
}

static int parse_netif(GKeyFile *config, const char *name, struct netif_config *netcfg)
{
	int ret;

	memset(netcfg, 0, sizeof(*netcfg));

	ret = parse_int(config, name, "mtu", &netcfg->mtu, defaults.mtu);
	if (netcfg->mtu && netcfg->mtu < 1024 + (int)sizeof(struct aoe_cfg_hdr))
	{
		logit(LOG_ERR, "%s: Requested MTU is too small", name);
		return FALSE;
	}
	ret &= parse_int(config, name, "buffers", &netcfg->buffers, defaults.buffers);
	if (ret && (netcfg->buffers < 0 || netcfg->buffers > MAX_BUFFERS))
	{
		logit(LOG_ERR, "%s: Requested buffer count is invalid", name);
		return FALSE;
	}

	return ret;
}

static int validate_config(GKeyFile *config)
{
	struct default_config oldcfg;
	struct device_config devcfg;
	struct netif_config netcfg;
	char **groups;
	unsigned i;
	int ret;

	/* Save the old configuration in case the new one is bogus */
	oldcfg = defaults;
	memset(&defaults, 0, sizeof(&defaults));

	ret = parse_defaults(config);
	ret &= parse_acls(config);

	groups = g_key_file_get_groups(config, NULL);
	for (i = 0; groups[i]; i++)
	{
		/* Skip special groups */
		if (!strcmp(groups[i], GRP_DEFAULTS) || !strcmp(groups[i], GRP_ACLS))
			continue;

		if (g_key_file_has_key(config, groups[i], "shelf", NULL))
		{
			ret &= parse_device(config, groups[i], &devcfg);
			destroy_device_config(&devcfg);
		}
		else
			ret &= parse_netif(config, groups[i], &netcfg);
	}
	g_strfreev(groups);

	if (ret)
		destroy_defaults(&oldcfg);
	else
	{
		destroy_defaults(&defaults);
		defaults = oldcfg;
	}
	return ret;
}

int get_device_config(const char *name, struct device_config *devcfg)
{
	return parse_device(global_config, name, devcfg);
}

int get_netif_config(const char *name, struct netif_config *netcfg)
{
	if (!g_key_file_has_group(global_config, name))
	{
		memset(netcfg, 0, sizeof(*netcfg));
		netcfg->buffers = defaults.buffers;
		return TRUE;
	}
	return parse_netif(global_config, name, netcfg);
}

static void do_load_config(const char *config_file, int reload)
{
	GKeyFile *new_config;
	GError *error = NULL;
	int ret;

	new_config = g_key_file_new();
	g_key_file_set_list_separator(new_config, ',');
	ret = g_key_file_load_from_file(new_config, config_file,
		G_KEY_FILE_NONE, &error);
	if (!ret)
	{
		logit(LOG_ERR, "%s the config file has failed: %s",
			reload ? "Reloading" : "Loading", error->message);
		g_error_free(error);
		return;
	}

	ret = validate_config(new_config);
	if (ret)
	{
		if (global_config)
			g_key_file_free(global_config);
		global_config = new_config;

		if (reload)
		{
			setup_ifaces();
			setup_devices();
			logit(LOG_INFO, "The configuration has been reloaded");
		}
	}
	else
	{
		logit(LOG_ERR, "The config file contains errors, %s",
			reload ? "not reloading" : "exiting");
		g_key_file_free(new_config);
	}
}

/**********************************************************************
 * Main program
 */

static struct option longopts[] =
{
	{ "config",	required_argument,	NULL, 'c' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "nofork",	no_argument,		NULL, 'n' },
	{ NULL }
};

static void usage(const char *prog, int error) G_GNUC_NORETURN;
static void usage(const char *prog, int error)
{
	printf("Usage: %s [options]\n", prog);
	printf("Valid options:\n");
	printf("\t-c file, --config file	Use the specified config. file\n");
	printf("\t-h, --help		This help text\n");
	printf("\t-d, --debug		Debug mode: don't fork, log traffic to stdout\n");
	printf("\t-n, --nofork		Don't fork to the background\n");
	exit(error);
}

static void write_pid_file(void)
{
	char buf[16];
	int ret;

	if (!defaults.pid_file)
		return;

	/* The configuration may change */
	pid_file = g_strdup(defaults.pid_file);

	pid_fd = open(pid_file, O_RDWR | O_CREAT, 0644);
	if (pid_fd == -1)
	{
		logerr("Failed to create the pid file '%s'", pid_file);
		exit_flag = 1;
	}

	if (lockf(pid_fd, F_LOCK, 0))
	{
		logit(LOG_ERR, "Another instance of the daemon seems "
			"to be already running, exiting");
		exit(1);
	}

	ret = read(pid_fd, buf, sizeof(buf));
	if (ret > 0)
	{
		logit(LOG_ERR, "Overriding stale lock file '%s'", pid_file);
		ftruncate(pid_fd, 0);
		lseek(pid_fd, 0, SEEK_SET);
	}

	snprintf(buf, sizeof(buf), "%u\n", (unsigned)getpid());
	write(pid_fd, buf, strlen(buf));
}

static void remove_pid_file(void)
{
	if (!pid_file || pid_fd == -1)
		return;
	unlink(pid_file);
	g_free(pid_file);
	close(pid_fd);
}

int main(int argc, char *const argv[])
{
	char *config_file = CONFIG_LOCATION;
	struct sigaction sa;
	int ret, c;

	while (1)
	{
		c = getopt_long(argc, argv, "c:hdn", longopts, NULL);
		if (c == -1)
			break;

		switch (c)
		{
			case 'c':
				config_file = optarg;
				break;
			case 'h':
				usage(argv[0], 0);
			case 'd':
				debug_flag++;
				nofork_flag++;
				break;
			case 'n':
				nofork_flag++;
				break;
			default:
				usage(argv[0], 1);

		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &sa, NULL);

	/* Test if the kernel supports eventfd. If it does, then AIO and
	 * epoll is also available */
	ret = eventfd(0, 0);
	if (ret == -1 && errno == ENOSYS)
	{
		fprintf(stderr, "This system does not have eventfd support\n");
		exit(1);
	}
	close(ret);

	do_load_config(config_file, FALSE);
	if (!global_config)
		exit(1);

	if (!nofork_flag && daemon(0, 0))
	{
		logerr("daemon() failed");
		exit(1);
	}

	if (!debug_flag)
	{
		openlog("ggaoed", LOG_PID, LOG_DAEMON);
		use_syslog = 1;
	}

	write_pid_file();

	clock_gettime(CLOCK_REALTIME, &startup);

	/* Initialize subsystems. Order is important. */
	mem_init();
	event_init();
	netmon_open();
	setup_ifaces();
	setup_devices();
	ctl_init();

	while (!exit_flag)
	{
		event_run();

		if (reload_flag)
		{
			logit(LOG_INFO, "Reload request received");
			do_load_config(config_file, TRUE);
			reload_flag = 0;
		}
	}

	ctl_done();
	netmon_close();
	done_devices();
	done_ifaces();
	mem_done();
	close(efd);

	if (dev_cache)
		blkid_put_cache(dev_cache);

	destroy_defaults(&defaults);
	g_key_file_free(global_config);
	remove_pid_file();

	return 0;
}
