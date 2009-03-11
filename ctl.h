#ifndef CTL_H
#define CTL_H

#include <sys/time.h>
#include <stdint.h>

/**********************************************************************
 * Constants
 */

/* Commands that can be sent through the control socket */
typedef enum {
	CTL_CMD_HELLO,
	CTL_CMD_GET_STATS,
	CTL_CMD_RELOAD
} ctl_command;

typedef enum {
	CTL_MSG_HELLO,
	CTL_MSG_UPTIME,
	CTL_MSG_DEVSTAT,
	CTL_MSG_NETSTAT,
	CTL_MSG_OK
} ctl_message;

#define CONFIG_LOCATION		SYSCONFDIR "/ggaoed.conf"
#define SOCKET_LOCATION		LOCALSTATEDIR "/run/ggaoed.sock"
#define PIDFILE_LOCATION	LOCALSTATEDIR "/run/ggaoed.pid"

#define CTL_PROTO_VERSION	1

#define CTL_MAX_PACKET		1024

/**********************************************************************
 * Data structures
 */

/* Device statistics */
struct device_stats
{
	uint64_t		read_req;
	uint64_t		read_bytes;
	uint64_t		write_req;
	uint64_t		write_bytes;
	uint32_t		other_req;
	struct timespec		req_time;
	uint64_t		queue_length;
	uint32_t		queue_stall;
	uint32_t		queue_full;
	uint32_t		ata_err;
	uint32_t		proto_err;

	/* Statistics about code internals */
	uint32_t		dev_io_max_hit;
};

/* Network interface statistics */
struct netif_stats
{
	uint64_t		rx_cnt;
	uint64_t		rx_bytes;
	uint64_t		tx_cnt;
	uint64_t		tx_bytes;
	uint32_t		dropped;
	uint32_t		ignored;
	uint32_t		buffers_full;
	uint64_t		processed;
	uint32_t		runs;

	/* Statistics about code internals */
	uint32_t		netio_recvfrom_max_hit;
};

struct msg_hello
{
	uint32_t		type;
	uint32_t		version;
};

struct msg_uptime
{
	uint32_t		type;
	uint32_t		uptime_sec;
	uint32_t		uptime_nsec;
};

struct msg_devstat
{
	uint32_t		type;
	struct device_stats	stats;
	char			name[0];
};

struct msg_netstat
{
	uint32_t		type;
	struct netif_stats	stats;
	char			name[0];
};

#endif /* CTL_H */
