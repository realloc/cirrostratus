#ifndef CTL_H
#define CTL_H

#include <sys/time.h>
#include <stdint.h>

#include "ggaoed.h"

/**********************************************************************
 * Constants
 */

/* Commands that can be sent through the control socket */
typedef enum {
	CTL_CMD_HELLO,
	CTL_CMD_GET_STATS,
	CTL_CMD_RELOAD,
	CTL_CMD_GET_CONFIG,
	CTL_CMD_GET_MACMASK,
	CTL_CMD_GET_RESERVE,
	CTL_CMD_CLEAR_STATS,
	CTL_CMD_CLEAR_CONFIG,
	CTL_CMD_CLEAR_MACMASK,
	CTL_CMD_CLEAR_RESERVE
} ctl_command;

typedef enum {
	CTL_MSG_HELLO,
	CTL_MSG_UPTIME,
	CTL_MSG_DEVSTAT,
	CTL_MSG_NETSTAT,
	CTL_MSG_OK,
	CTL_MSG_MACLIST
} ctl_message;

#define CONFIG_LOCATION		SYSCONFDIR "/ggaoed.conf"
#define SOCKET_LOCATION		LOCALSTATEDIR "/run/ggaoed.sock"
#define PIDFILE_LOCATION	LOCALSTATEDIR "/run/ggaoed.pid"

#define CTL_PROTO_VERSION	1

#define CTL_MAX_PACKET		4096

/**********************************************************************
 * Data structures
 */

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

struct msg_maclist
{
	uint32_t		type;
	struct acl_map		list;
	char			name[0];
};

struct msg_config
{
	uint32_t		type;
	struct config_map	cfg;
	char			name[0];
};

#endif /* CTL_H */
