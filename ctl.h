#ifndef CTL_H
#define CTL_H

#include <sys/time.h>
#include <stdint.h>

/**********************************************************************
 * Constants
 */

/* Commands that can be sent through the control socket */
typedef enum {
	CTL_CMD_GET_STATS,
	CTL_CMD_RELOAD
} ctl_command;

#define CONFIG_LOCATION		SYSCONFDIR "/ggaoed.conf"
#define SOCKET_LOCATION		LOCALSTATEDIR "/run/ggaoed.sock"
#define PIDFILE_LOCATION	LOCALSTATEDIR "/run/ggaoed.pid"

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
	struct timeval		req_time;
	uint64_t		queue_len;
	uint32_t		queue_stall;
	uint32_t		queue_full;
	uint32_t		ata_err;
	uint32_t		proto_err;

	/* Statistics about code internals */
	uint32_t		compress_run;
	uint32_t		compress_entries;
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
	uint32_t		buffers_full;
	uint64_t		processed;
	uint32_t		runs;

	/* Statistics about code internals */
	uint32_t		netio_recvfrom_max_hit;
};

#endif /* CTL_H */
