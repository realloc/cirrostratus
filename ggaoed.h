#ifndef GGAOED_H
#define GGAOED_H

#include <sys/uio.h>
#include <libaio.h>
#include <stdint.h>
#include <syslog.h>

#include <glib.h>

#include "aoe.h"

#define INTERNAL		__attribute__((__visibility__("internal")))

/**********************************************************************
 * Constants
 */

#define SHELF_BCAST		0xffff
#define SLOT_BCAST		0xff

#define MAX_QUEUE_LEN		65535
#define DEF_QUEUE_LEN		64

#define DEF_RING_SIZE		(4 * 1024)

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
	int			send_buf_size;
	int			recv_buf_size;
	double			max_delay;
	double			merge_delay;
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
	uint64_t		read_cnt;
	uint64_t		read_bytes;
	struct timespec		read_time;
	uint64_t		write_cnt;
	uint64_t		write_bytes;
	struct timespec		write_time;
	uint32_t		other_cnt;
	struct timespec		other_time;
	uint64_t		io_slots;
	uint64_t		io_runs;
	uint64_t		queue_length;
	uint32_t		queue_stall;
	uint32_t		queue_over;
	uint32_t		ata_err;
	uint32_t		proto_err;
};

/* Network interface statistics */
struct netif_stats
{
	uint64_t		rx_cnt;
	uint64_t		rx_bytes;
	uint64_t		rx_runs;
	uint64_t		tx_cnt;
	uint64_t		tx_bytes;
	uint64_t		tx_runs;
	uint32_t		rx_buffers_full;
	uint32_t		tx_buffers_full;
	uint32_t		dropped;
	uint32_t		ignored;
	uint32_t		broadcast;
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
	long			merge_delay;

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
	int			send_buf_size;
	int			recv_buf_size;
};

/* Event handler context */
struct event_ctx
{
	io_callback		callback;
	void			*data;
};

/* Elements of a device's I/O queue */
struct device;
struct queue_item
{
	struct device		*dev;
	struct netif		*iface;

	struct timespec		start;

	void			*buf;
	unsigned		bufsize;
	unsigned		length;

	unsigned long long	offset;

	/* Flags */
	int			dynalloc: 1;
	int			is_ata: 1;
	int			is_write: 1;

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

/* Data structure used for request merging */
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
	char			*name;
	unsigned long long	size;
	int			fd;

	int			io_stall: 1;
	int			is_active: 1;
	int			timer_armed: 1;

	/* Number of requests in flight */
	int			queue_length;

	int			event_fd;
	int			timer_fd;

	struct device_config	cfg;
	struct device_stats	stats;

	struct event_ctx	event_ctx;
	struct event_ctx	timer_ctx;

	/* AoE Command 1, configuration state */
	struct config_map	*aoe_conf;
	/* AoE Command 2, MAC mask list */
	struct acl_map		*mac_mask;
	/* AoE Command 3, reserve/release */
	struct acl_map		*reserve;

	io_context_t		aio_ctx;

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

/* Memory mapped ring structure */
struct ring
{
	/* Total length of the ring buffer */
	unsigned		len;
	/* Number of frames (packets) in the ring buffer */
	unsigned		cnt;
	/* The index of the next frame to use */
	unsigned		idx;
	/* Frame size in the ring buffer */
	unsigned		frame_size;
	/* Block size of the ring buffer */
	unsigned		block_size;
	/* Pointers to the individual frames */
	void			**frames;
};

/* State of a network interface */
struct netif
{
	char			*name;
	int			ifindex;
	int			mtu;
	int			fd;

	/* Flags */
	int			congested: 1;
	int			is_active: 1;

	struct netif_config	cfg;
	struct netif_stats	stats;

	struct event_ctx	event_ctx;

	struct ether_addr	mac;

	struct ring		rx_ring;
	struct ring		tx_ring;

	/* The address of the memory-mapped rings (first RX, then TX) */
	void			*ring_ptr;
	/* The length of the mapped area */
	unsigned		ring_len;

	/* The length of the frame header in the rings */
	int			tp_hdrlen;

	/* Devices that can be accessed on this interface */
	GPtrArray		*devices;

	/* Completed requests waiting to be sent */
	GPtrArray		*deferred;

	/* Chaining interfaces for processing */
	GList			chain;
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
void run_ifaces(void) INTERNAL;

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
void send_advertisment(struct device *dev, struct netif *iface) INTERNAL;

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
extern GQueue active_devs;
extern GPtrArray *ifaces;
extern GQueue active_ifaces;

#endif /* GGAOED_H */
