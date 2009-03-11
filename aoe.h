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

/* AoE commands */
#define AOE_CMD_ATA		0	/* Issue ATA Command */
#define AOE_CMD_CFG		1	/* Query Config Information */

/* Start of vendor-specific commands */
#define AOE_CMD_VENDOR		240

/* Config string query/set subcommands */
#define AOE_CFG_READ		0	/* Read config string */
#define AOE_CFG_TEST		1	/* Test config string */
#define AOE_CFG_TEST_PREFIX	2	/* Test config string prefix */
#define AOE_CFG_SET		3	/* Set config string if empty */
#define AOE_CFG_FORCE_SET	4	/* Force set config string */


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
} __attribute__ ((packed));

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
} __attribute__ ((packed));

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
} __attribute__ ((packed));

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
