#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/**********************************************************************
 * Data structures
 */

/* Header for RTNetlink requests */
struct nl_req
{
	struct nlmsghdr		hdr;
	struct rtgenmsg		familysel;
};

/**********************************************************************
 * Global variables
 */

/* The netlink socket descriptor */
static int nl_fd = -1;

/* Netlink sequence number */
static uint32_t nl_seq;

/* Netlink event context */
static struct event_ctx nl_ctx;

/* Receive buffer */
static char *recvbuf;
static int recvlen;

static void netmon_read(uint32_t events, void *data);

/**********************************************************************
 * Functions
 */

void netmon_open(void)
{
	struct sockaddr_nl addr;
	int ret;

	recvlen = 1024;
	recvbuf = g_malloc(recvlen);

	nl_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (nl_fd == -1)
	{
		logerr("Failed to open netlink socket");
		exit_flag = 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK;

	ret = bind(nl_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1)
	{
		logerr("bind(RTMGRP_LINK) failed");
		exit_flag = 1;
	}

	nl_ctx.callback = netmon_read;
	add_fd(nl_fd, &nl_ctx);
}

void netmon_enumerate(void)
{
	struct sockaddr_nl to_addr;
	struct nl_req req;
	int ret;

	memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = sizeof(req);
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_seq = ++nl_seq;

	req.familysel.rtgen_family = AF_PACKET;

	memset(&to_addr, 0, sizeof(to_addr));
	to_addr.nl_family = AF_NETLINK;

	ret = sendto(nl_fd, &req, sizeof(req), 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
	if (ret == -1)
		logerr("Failed to send enumeration request over netlink");
}

static void parse_attrs(struct rtattr *first, int attlen,
	struct rtattr *attrs[], unsigned max_attr)
{
	memset(attrs, 0, (max_attr + 1) * sizeof(*attrs));

	for (; RTA_OK(first, attlen); first = RTA_NEXT(first, attlen))
		if (first->rta_type <= max_attr)
			attrs[first->rta_type] = first;
}

static void add_link(struct nlmsghdr *hdr)
{
	struct rtattr *attrs[IFLA_MAX + 1];
	struct ifinfomsg *ifmsg;
	unsigned attlen;
	int mtu;

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg)))
		return;

	attlen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifmsg));
	ifmsg = (struct ifinfomsg *)NLMSG_DATA(hdr);

	parse_attrs(IFLA_RTA(ifmsg), attlen, attrs, IFLA_MAX);
	if (!attrs[IFLA_IFNAME] || !attrs[IFLA_ADDRESS] || !attrs[IFLA_MTU])
		return;

	if ((RTA_PAYLOAD(attrs[IFLA_ADDRESS]) != 6 || ifmsg->ifi_type != ARPHRD_ETHER)
			&& !(ifmsg->ifi_flags & IFF_LOOPBACK))
	{
		logit(LOG_DEBUG, "%s: Not an ethernet interface, ignoring",
			(char *)RTA_DATA(attrs[IFLA_IFNAME]));
		return;
	}

	mtu = *(int *)RTA_DATA(attrs[IFLA_MTU]);

	/* Loopback may have a too large MTU */
	if (mtu > 16384)
		mtu = 16384;

	if (ifmsg->ifi_flags & IFF_UP)
		validate_iface(RTA_DATA(attrs[IFLA_IFNAME]), ifmsg->ifi_index,
			mtu, RTA_DATA(attrs[IFLA_ADDRESS]));
	else
		invalidate_iface(ifmsg->ifi_index);
}

static void del_link(struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifmsg;

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifmsg)))
		return;

	ifmsg = (struct ifinfomsg *)NLMSG_DATA(hdr);

	invalidate_iface(ifmsg->ifi_index);
}

static void netmon_read(uint32_t events G_GNUC_UNUSED, void *data)
{
	struct sockaddr_nl from_addr;
	struct nlmsghdr *msg;
	socklen_t addrlen;
	int len;

	addrlen = sizeof(from_addr);
	len = recvfrom(nl_fd, recvbuf, recvlen, MSG_TRUNC | MSG_DONTWAIT,
		(struct sockaddr *)&from_addr, &addrlen);
	if (!len)
		return;
	if (len == -1)
	{
		logerr("Netlink read error");
		netmon_close();
	}
	if (len > recvlen)
	{
		/* The buffer was too small. Increase it and request a
		 * new enumeration */
		recvlen <<= 1;
		recvbuf = g_realloc(recvbuf, recvlen);
		netmon_enumerate();
		return;
	}

	for (msg = (struct nlmsghdr *)recvbuf; NLMSG_OK(msg, (unsigned)len);
			msg = NLMSG_NEXT(msg, len))
	{
		if (msg->nlmsg_type == NLMSG_DONE)
			break;
		else if (msg->nlmsg_type == RTM_NEWLINK)
			add_link(msg);
		else if (msg->nlmsg_type == RTM_DELLINK)
			del_link(msg);
	}
}

void netmon_close(void)
{
	if (nl_fd == -1)
		return;

	del_fd(nl_fd);
	close(nl_fd);
	nl_fd = -1;

	g_free(recvbuf);
	recvbuf = NULL;
}
