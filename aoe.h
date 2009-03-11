#ifndef AOE_H
#define AOE_H

#include <net/ethernet.h>
#include <endian.h>

/* Version of the AoE protocol we implement */
#define AOE_VERSION		1

/* Error codes for the error field in the AoE header */
#define AOE_ERR_BADCMD		1	/* Unrecognized command code */
#define AOE_ERR_BADARG		2	/* Bad argument parameter */
#define AOE_ERR_DEVUNAVAIL	3	/* Device unavailable */
#define AOE_ERR_CFG_SET		4	/* Config string present */
#define AOE_ERR_UNSUPVER	5	/* Unsupported version */
#define AOE_ERR_RESERVED	6	/* The target is reserved */

/* AoE commands */
#define AOE_CMD_ATA		0	/* Issue ATA Command */
#define AOE_CMD_CFG		1	/* Query Config Information */
#define AOE_CMD_MASK		2	/* Mac Mask List */
#define AOE_CMD_RESERVE		3	/* Reserve / Release */

/* Start of vendor-specific commands */
#define AOE_CMD_VENDOR		240

/* Config string query/set subcommands */
#define AOE_CFG_READ		0	/* Read config string */
#define AOE_CFG_TEST		1	/* Test config string */
#define AOE_CFG_TEST_PREFIX	2	/* Test config string prefix */
#define AOE_CFG_SET		3	/* Set config string if empty */
#define AOE_CFG_FORCE_SET	4	/* Force set config string */

/* Mac Mask List management subcommands */
#define AOE_MCMD_READ		0	/* Read Mac Mask List */
#define AOE_MCMD_EDIT		1	/* Edit Mac Mask List */

/* Mac Mask List management error codes */
#define AOE_MERROR_UNSPEC	1	/* Unspecified Error */
#define AOE_MERROR_BADDIR	2	/* Bad DCmd directive */
#define AOE_MERROR_FULL		3	/* MAC list full */

/* Mac Mask List editing directoves */
#define AOE_DCMD_NONE		0	/* No directive */
#define AOE_DCMD_ADD		1	/* Add MAC address */
#define AOE_DCMD_DELETE		2	/* Delete MAC address */

/* Reserve/release subcommands */
#define AOE_RESERVE_READ	0	/* Read the reserve list */
#define AOE_RESERVE_SET		1	/* Set the reserve list */
#define AOE_RESERVE_FORCESET	2	/* Force set the reserve list */

struct aoe_hdr
{
	struct ether_header	addr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char		_dummy:2;
	unsigned char		is_error:1;
	unsigned char		is_response:1;
	unsigned char		version:4;
#else
	unsigned char		version:4;
	unsigned char		is_response:1;
	unsigned char		is_error:1;
	unsigned char		_dummy:2;
#endif
	unsigned char		error;
	unsigned short		shelf;
	unsigned char		slot;
	unsigned char		cmd;
	unsigned int		tag;
} __attribute__((packed));

struct aoe_ata_hdr
{
	struct aoe_hdr		aoehdr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char		is_write:1;
	unsigned char		is_async:1;
	unsigned char		_dummy1:2;
	unsigned char		devhead:1;
	unsigned char		_dummy2:1;
	unsigned char		is_lba48:1;
	unsigned char		_dummy3:1;
#else
	unsigned char		_dummy3:1;
	unsigned char		is_lba48:1;
	unsigned char		_dummy2:1;
	unsigned char		devhead:1;
	unsigned char		_dummy1:2;
	unsigned char		is_async:1;
	unsigned char		is_write:1;
#endif
	unsigned char		err_feature;	/* Check linux/hdreg.h for status codes */
	unsigned char		nsect;
	unsigned char		cmdstat;
	unsigned char		lba[6];
	unsigned char		_reserved[2];
} __attribute__((packed));

struct aoe_cfg_hdr
{
	struct aoe_hdr		aoehdr;
	unsigned short		queuelen;
	unsigned short		firmware;
	unsigned char		maxsect;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char		ccmd:4;
	unsigned char		version:4;
#else
	unsigned char		version:4;
	unsigned char		ccmd:4;
#endif
	unsigned short		cfg_len;
} __attribute__((packed));

struct aoe_macmask_dir
{
	unsigned char		reserved;
	unsigned char		dcmd;
	struct ether_addr	addr;
} __attribute__((packed));

struct aoe_macmask_hdr
{
	struct aoe_hdr		aoehdr;
	unsigned char		reserved;
	unsigned char		mcmd;
	unsigned char		merror;
	unsigned char		dcnt;
	struct aoe_macmask_dir	directives[0];
} __attribute__((packed));

struct aoe_reserve_hdr
{
	struct aoe_hdr		aoehdr;
	unsigned char		rcmd;
	unsigned char		nmacs;
	struct ether_addr	addrs[0];
} __attribute__((packed));

#ifndef ETH_P_AOE
#define ETH_P_AOE		0x88a2
#endif

/* Taken from linux/ata.h */
enum
{
	ATA_BUSY		= (1 << 7),	/* BSY status bit */
	ATA_DRDY		= (1 << 6),	/* device ready */
	ATA_DF			= (1 << 5),	/* device fault */
	ATA_DRQ			= (1 << 3),	/* data request i/o */
	ATA_ERR			= (1 << 0),	/* have an error */
} ata_status;

/* Taken from linux/ata.h */
enum
{
	ATA_ICRC		= (1 << 7),	/* interface CRC error */
	ATA_UNC			= (1 << 6),	/* uncorrectable media error */
	ATA_IDNF		= (1 << 4),	/* ID not found */
	ATA_ABORTED		= (1 << 2),	/* command aborted */
} ata_err;

#endif /* AOE_H */
