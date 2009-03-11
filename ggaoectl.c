#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ctl.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <glib.h>

/**********************************************************************
 * Global variables
 */

/* Socket descriptor */
static int ctl_fd;

/* Sampling interval */
static int interval = 1;

/* Hash tables holding the previous and new statistics for devices/interfaces */
static GHashTable *old_dev, *old_net, *new_dev, *new_net;

/**********************************************************************
 * Functions
 */

/* Read a stat record from the daemon */
static int read_stat(GHashTable *dst, unsigned size)
{
	uint32_t len;
	void *data;
	char *name;
	int ret;

	ret = read(ctl_fd, &len, sizeof(len));
	if (ret != sizeof(len))
		return -1;
	name = g_malloc(len + 1);
	ret = read(ctl_fd, name, len);
	if (ret != (int)len)
	{
		g_free(name);
		return -1;
	}
	name[len] = '\0';

	ret = read(ctl_fd, &len, sizeof(len));
	if (ret != sizeof(len) || len != size)
	{
		g_free(name);
		return -1;
	}

	data = g_malloc(size);
	ret = read(ctl_fd, data, size);
	if (ret != (int)size)
	{
		g_free(name);
		g_free(data);
		return -1;
	}

	g_hash_table_insert(dst, name, data);
	return 0;
}

/* Calculate the max. name length of devices/interfaces */
static void max_name_length(void *key, void *value G_GNUC_UNUSED, void *ptr)
{
	unsigned *len = ptr;
	char *name = key;

	if (strlen(name) > *len)
		*len = strlen(name);
}

#define DIFF(field)	diff.field = new->field - old->field
static void print_dev_record(void *key, void *value, void *ptr)
{
	struct device_stats *new = value, *old, diff;
	double reqtime, qlen;
	unsigned *len = ptr, allreq;
	char *name = key;

	old = g_hash_table_lookup(old_dev, name);
	if (!old)
	{
		old = g_new0(struct device_stats, 1);
		g_hash_table_insert(old_dev, g_strdup(name), old);
	}

	DIFF(read_req);
	DIFF(read_bytes);
	DIFF(write_req);
	DIFF(write_bytes);
	DIFF(other_req);
	DIFF(queue_len);
	DIFF(queue_stall);
	DIFF(queue_full);
	DIFF(ata_err);
	DIFF(proto_err);

	diff.req_time.tv_sec = new->req_time.tv_sec - old->req_time.tv_sec;
	diff.req_time.tv_nsec = new->req_time.tv_nsec - old->req_time.tv_nsec;
	if (diff.req_time.tv_nsec < 0)
	{
		diff.req_time.tv_nsec += 1000000000;
		--diff.req_time.tv_sec;
	}

	allreq = diff.read_req + diff.write_req + diff.other_req;
	if (!allreq)
	{
		reqtime = 0;
		qlen = 0;
	}
	else
	{
		/* reqtime is in milliseconds */
		reqtime = (diff.req_time.tv_sec * 1000 + (double)diff.req_time.tv_nsec / 1000000) / allreq;
		qlen = (double)diff.queue_len / allreq;
	}

	printf("%-*s %8.1f %10.2f %8.1f %10.2f %3u %6.2f %2u %2u %2u %2u %8.2f\n", *len, name,
		(double)diff.read_req / interval,
		(double)diff.read_bytes / 1024 / interval,
		(double)diff.write_req / interval,
		(double)diff.write_bytes / 1024 / interval,
		(unsigned)diff.other_req,
		qlen,
		(unsigned)diff.queue_stall,
		(unsigned)diff.queue_full,
		(unsigned)diff.ata_err,
		(unsigned)diff.proto_err,
		reqtime);
}

static void print_dev_stats(int argc, char *const argv[], unsigned len)
{
	int i;

	printf("%-*s   rrqm/s      rKb/s   wrqm/s      wKb/s oth avgqsz qs qf ae pe    svctm\n", len, "dev");
	if (!argc)
	{
		g_hash_table_foreach(new_dev, print_dev_record, &len);
		return;
	}

	for (i = 0; i < argc; i++)
	{
		struct device_stats *rec;

		rec = g_hash_table_lookup(new_dev, argv[i]);
		if (!rec)
		{
			rec = g_new0(struct device_stats, 1);
			g_hash_table_insert(new_dev, g_strdup(argv[i]), rec);
		}
		print_dev_record(argv[i], rec, &len);
	}
}

static void print_net_record(void *key, void *value, void *ptr)
{
	struct netif_stats *new = value, *old, diff;
	unsigned *len = ptr;
	char *name = key;
	double avgr;

	old = g_hash_table_lookup(old_net, name);
	if (!old)
	{
		old = g_new0(struct netif_stats, 1);
		g_hash_table_insert(old_net, g_strdup(name), old);
	}

	DIFF(rx_cnt);
	DIFF(rx_bytes);
	DIFF(tx_cnt);
	DIFF(tx_bytes);
	DIFF(dropped);
	DIFF(processed);
	DIFF(runs);

	if (diff.runs)
		avgr = (double)diff.processed / diff.runs;
	else
		avgr = 0;

	printf("%-*s %8.1f %10.2f %8.1f %10.2f %3u %6.2f\n", *len, name,
		(double)diff.rx_cnt / interval,
		(double)diff.rx_bytes / 1024 / interval,
		(double)diff.tx_cnt / interval,
		(double)diff.tx_bytes / 1024 / interval,
		(unsigned)diff.dropped,
		avgr);
}

static void print_net_stats(int argc, char *const argv[], unsigned len)
{
	int i;

	printf("%-*s   rrqm/s      rKb/s   wrqm/s      wKb/s drp   avgr\n", len, "net");

	if (!argc)
	{
		g_hash_table_foreach(new_net, print_net_record, &len);
		return;
	}

	for (i = 0; i < argc; i++)
	{
		struct netif_stats *rec;

		rec = g_hash_table_lookup(new_net, argv[i]);
		if (!rec)
		{
			rec = g_new0(struct netif_stats, 1);
			g_hash_table_insert(new_net, g_strdup(argv[i]), rec);
		}
		print_net_record(argv[i], rec, &len);
	}
}

static void do_monitor(int argc, char *const argv[])
{
	uint32_t val, i;
	unsigned len;
	int ret;

	old_dev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	old_net = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	new_dev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	new_net = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	while (1)
	{
		g_hash_table_destroy(old_dev);
		g_hash_table_destroy(old_net);
		old_dev = new_dev;
		old_net = new_net;
		new_dev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		new_net = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

		val = CTL_CMD_GET_STATS;
		ret = write(ctl_fd, &val, sizeof(val));
		if (ret != sizeof(val))
		{
			fprintf(stderr, "Failed to send the command\n");
			exit(1);
		}

		/* Device statistics */
		ret = read(ctl_fd, &val, sizeof(val));
		if (ret != sizeof(val))
			return;
		for (i = 0; i < val; i++)
		{
			ret = read_stat(new_dev, sizeof(struct device_stats));
			if (ret)
				return;
		}

		/* Network statistics */
		ret = read(ctl_fd, &val, sizeof(val));
		if (ret != sizeof(val))
		{
			fprintf(stderr, "Receiving statistics has failed\n");
			exit(1);
		}
		for (i = 0; i < val; i++)
		{
			ret = read_stat(new_net, sizeof(struct netif_stats));
			if (ret)
				return;
		}

		/* Min. size of the name field */
		len = 4;

		if (!argc)
		{
			g_hash_table_foreach(new_dev, max_name_length, &len);
			g_hash_table_foreach(new_net, max_name_length, &len);
		}
		else
		{
			for (i = 0; i < (unsigned)argc; i++)
				max_name_length(argv[i], NULL, &len);
		}

		print_dev_stats(argc, argv, len);
		print_net_stats(argc, argv, len);
		printf("\n");

		sleep(interval);
	}
}

static void do_reload(void)
{
	uint32_t cmd;
	int ret;

	cmd = CTL_CMD_RELOAD;
	ret = write(ctl_fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
	{
		fprintf(stderr, "Failed to send the command\n");
		exit(1);
	}
	ret = read(ctl_fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
	{
		fprintf(stderr, "Failed to receive the status\n");
		exit(1);
	}
}

static struct option longopts[] =
{
	{ "config",	required_argument,	NULL, 'c' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ NULL }
};

static void usage(const char *prog, int error) G_GNUC_NORETURN;
static void usage(const char *prog, int error)
{
	printf("Usage: %s [options] <command> [args]\n", prog);
	printf("Valid options:\n");
	printf("\t-c FILE, --config FILE	Use the specified config. file\n");
	printf("\t-h, --help		This help text\n");
	printf("\t-i, --interval		Monitoring time interval\n");
	printf("Valid commands:\n");
	printf("\tmonitor [name...]	Monitor devices/interfaces\n");
	printf("\treload			Reload the configuration file\n");
	exit(error);
}

int main(int argc, char *const argv[])
{
	char *config_file = CONFIG_LOCATION, *ctl_socket;
	struct sockaddr_un sa;
	GError *error = NULL;
	GKeyFile *config;
	int ret, c;

	while (1)
	{
		c = getopt_long(argc, argv, "c:hi:", longopts, NULL);
		if (c == -1)
			break;

		switch (c)
		{
			case 'c':
				config_file = optarg;
				break;
			case 'h':
				usage(argv[0], 0);
			case 'i':
				interval = atoi(optarg);
				if (interval < 1)
				{
					fprintf(stderr, "Illegal interval\n");
					exit(1);
				}
				break;
			default:
				usage(argv[0], 1);

		}
	}

	argv += optind;
	argc -= optind;

	if (!argc)
	{
		fprintf(stderr, "You must specify a command.\n");
		exit(1);
	}

	config = g_key_file_new();
	g_key_file_set_list_separator(config, ',');
	ret = g_key_file_load_from_file(config, config_file, G_KEY_FILE_NONE, &error);
	if (!ret)
	{
		fprintf(stderr, "Loading the config file has failed: %s\n",
			error->message);
		g_error_free(error);
		exit(1);
	}

	ctl_socket = g_key_file_get_string(config, "defaults", "control-socket", NULL);
	if (!ctl_socket)
		ctl_socket = g_strdup(SOCKET_LOCATION);

	ctl_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ctl_fd == -1)
	{
		perror("socket()");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", ctl_socket);
	ret = connect(ctl_fd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret)
	{
		perror("connect()");
		exit(1);
	}
	
	if (!strcmp(argv[0], "monitor"))
		do_monitor(argc - 1, argv + 1);
	else if (!strcmp(argv[0], "reload"))
		do_reload();
	else
	{
		fprintf(stderr, "Unknown command\n");
		close(ctl_fd);
		exit(1);
	}
	
	close(ctl_fd);

	g_key_file_free(config);
	g_free(ctl_socket);

	return 0;
}
