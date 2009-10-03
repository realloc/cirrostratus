#ifndef GGAOED_H
#define GGAOED_H

#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif
#include <sys/epoll.h>
#include <sys/uio.h>
#include <libaio.h>
#include <syslog.h>

#include <glib.h>

#include "aoe.h"

#define INTERNAL		__attribute__((__visibility__("internal")))

/**********************************************************************
 * Constants
 */

#define SHELF_BCAST		0xffff
#define SLOT_BCAST		0xff

#define MIN_QUEUE_LEN		4
#define MAX_QUEUE_LEN		1024
#define DEF_QUEUE_LEN		64

#define DEF_RING_SIZE		256
#define MAX_RING_SIZE		(128 * 1024)

#define MAX_LBA28		0x0fffffffLL
#define MAX_LBA48		0x0000ffffffffffffLL

/* Max. number of I/O requests to merge in a single submission */
#define MAX_MERGE		32

#define CONFIG_MAP_MAGIC	0x38a0bfae
#define ACL_MAP_MAGIC		0xe92a716b

/**********************************************************************
 * Data types
 */

/* I/O event handler callback prototype */
typedef void (*io_callback)(uint32_t events, void *data);

/* Configuration defaults */
struct default_config
{
	int			queue_length;
	int			direct_io;
	int			trace_io;
	GPtrArray		*interfaces;
	GPtrArray		*acls;
	int			mtu;
	int			ring_size;
	char			*pid_file;
	char			*ctl_socket;
	char			*statedir;
};

/* Ethernet address padded for faster lookup */
union padded_addr
{
	struct ether_addr	e;
	uint64_t		u;
};

/* ACL map structure */
struct acl_map
{
	uint32_t		magic;
	uint32_t		length;
	union padded_addr	entries[255];
};

/* Device configuration page */
struct config_map
{
	uint32_t		magic;
	uint32_t		length;
	unsigned char		data[1024];
};

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
	uint64_t		queue_merge;
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
	uint32_t		broadcast;

	/* Statistics about code internals */
	uint32_t		netio_recvfrom_max_hit;
};

/* Device configuration */
struct device_config
{
	char			*path;
	/* The shelf number is in network byte order */
	unsigned		shelf;
	unsigned		slot;
	int			queue_length;
	int			direct_io;
	int			trace_io;
	int			read_only;
	int			broadcast;
	long			max_delay;

	/* Patterns of allowed interfaces */
	GPtrArray		*iface_patterns;

	/* ACLs */
	struct acl_map		*accept;
	struct acl_map		*deny;
};

/* Network interface configuration */
struct netif_config
{
	int			mtu;
	int			ring_size;
};

/* Event handler context */
struct event_ctx
{
	io_callback		callback;
};

/* Elements of a device's I/O queue */
struct device;
struct queue_item
{
	struct device		*dev;

	struct timespec		start;
	struct netif		*iface;

	void			*buf;
	unsigned		bufsize;
	unsigned		length;
	unsigned		dynalloc;

	unsigned long long	offset;
	int			is_write;

	unsigned		hdrlen;
	union
	{
		struct aoe_hdr		aoe_hdr;
		struct aoe_ata_hdr	ata_hdr;
		struct aoe_cfg_hdr	cfg_hdr;
		struct aoe_macmask_hdr	mask_hdr;
		struct aoe_reserve_hdr	reserve_hdr;
	};
};

struct submit_slot
{
	unsigned long long	offset;
	int			is_write;
	unsigned		num_iov;

	struct device		*dev;
	struct iocb		iocb;
	GList			chain;
	struct iovec		iov[MAX_MERGE];
	struct queue_item	*items[MAX_MERGE];
};

/* State of an exported device */
struct device
{
	/* This must be the first element of the struct */
	struct event_ctx	event_ctx;
	int			event_fd;

	int			fd;

	int			io_stall;
	int			is_active;

	char			*name;
	unsigned long long	size;
	struct device_config	cfg;
	struct device_stats	stats;

	/* AoE Command 1, configuration state */
	struct config_map	*aoe_conf;
	/* AoE Command 2, MAC mask list */
	struct acl_map		*mac_mask;
	/* AoE Command 3, reserve/release */
	struct acl_map		*reserve;

	io_context_t		aio_ctx;

	int			queue_length;
	/* List of submitted I/O requests. Items: struct submit_slot */
	GQueue			active;
	/* List of requests that could not be submitted immediately */
	GPtrArray		*deferred;

	/* Chaining devices for processing */
	GList			chain;

	/* List of attached interfaces */
	GPtrArray		*ifaces;
};

/* ACL definition */
struct acl
{
	char			*name;
	struct acl_map		*map;
};

/* State of a network interface */
struct netif
{
	/* This must be the first element of the struct */
	struct event_ctx	event_ctx;

	struct netif_config	cfg;
	struct netif_stats	stats;

	char			*name;
	int			ifindex;
	int			mtu;
	int			fd;

	int			congested;
	GPtrArray		*deferred;

	struct ether_addr	mac;

	void			*ringptr;
	unsigned		ringlen;
	void			**ring;
	unsigned		ringcnt;
	unsigned		ringidx;
	unsigned		frame_size;
	int			tp_hdrlen;

	/* Devices that can be accessed on this interface */
	GPtrArray		*devices;
};

/**********************************************************************
 * Prototypes
 */

void logit(int level, const char *fmt, ...) G_GNUC_PRINTF(2, 3) INTERNAL;
#define logerr(fmt, ...) \
	logit(LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno))
#define devlog(dev, level, fmt, ...) \
	logit(level, "disk/%s: " fmt, dev->name, ##__VA_ARGS__)
#define deverr(dev, fmt, ...) \
	devlog(dev, LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno))
#define netlog(iface, level, fmt, ...) \
	logit(level, "net/%s: " fmt, iface->name, ##__VA_ARGS__)
#define neterr(iface, fmt, ...) \
	netlog(iface, LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno))

void validate_iface(const char *name, int ifindex, int mtu, const char *macaddr) INTERNAL;
void invalidate_iface(int ifindex) INTERNAL;
void setup_ifaces(void) INTERNAL;
void done_ifaces(void) INTERNAL;
void send_response(struct queue_item *q) INTERNAL;
int match_acl(const struct acl_map *acls, const void *mac) INTERNAL G_GNUC_PURE;
int add_one_acl(struct acl_map *acls, const struct ether_addr *addr) INTERNAL;
void del_one_acl(struct acl_map *acls, const struct ether_addr *addr) INTERNAL;

void *alloc_packet(unsigned size) INTERNAL G_GNUC_MALLOC;
void free_packet(void *buf, unsigned size) INTERNAL;
void mem_init(void) INTERNAL;
void mem_done(void) INTERNAL;

void netmon_open(void) INTERNAL;
void netmon_enumerate(void) INTERNAL;
void netmon_close(void) INTERNAL;

void add_fd(int fd, struct event_ctx *ctx) INTERNAL;
void del_fd(int fd) INTERNAL;
void modify_fd(int fd, struct event_ctx *ctx, uint32_t events) INTERNAL;

void process_request(struct netif *iface, struct device *device,
	void *buf, int len, const struct timespec *tv) INTERNAL;
void attach_device(void *dev, void *iface) G_GNUC_INTERNAL;
void detach_device(struct netif *iface, struct device *device) INTERNAL;
void setup_devices(void) INTERNAL;
void done_devices(void) INTERNAL;
void drop_request(struct queue_item *q) INTERNAL;
void run_devices(void) INTERNAL;

int match_patternlist(const GPtrArray *list, const char *str) INTERNAL G_GNUC_PURE;
void build_patternlist(GPtrArray *list, char **elements) INTERNAL;
void free_patternlist(GPtrArray *list) INTERNAL;
int get_device_config(const char *name, struct device_config *devcfg) INTERNAL;
void destroy_device_config(struct device_config *devcfg) INTERNAL;
int get_netif_config(const char *name, struct netif_config *netcfg) INTERNAL;
unsigned long long human_format(unsigned long long size, const char **unit) INTERNAL;

void ctl_init(void) INTERNAL;
void ctl_done(void) INTERNAL;

/**********************************************************************
 * Global variables
 */

extern GKeyFile *global_config;
extern volatile int exit_flag;
extern volatile int reload_flag;
extern struct default_config defaults;
extern struct timespec startup;

extern GPtrArray *devices;
extern GPtrArray *ifaces;

#endif /* GGAOED_H */
