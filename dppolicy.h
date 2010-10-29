#ifndef DPPOLICY_H
#define	DPPOLICY_H

#include "ggaoed.h"

/**********************************************************************
 * Prototypes
 */

/* Mirroring algoritm for data protection */
struct cs_netlist* cs_dppolicy_mirror_encode(struct queue_item *q);
int cs_dppolicy_mirror_decode(struct queue_item *q, struct cs_netlist *nl);

/**********************************************************************
 * Global variables
 */

#define CS_DP_MAX_REPLICAS      16

/*
 * name - name of algoritm
 * encode/decode - name of encode/decode function
 * k - count of block with input data
 * m - count of block with coding data
 */
static const struct cs_dppolicy dppolicys[] =
{
	{.name = "null", .encode = cs_dppolicy_mirror_encode, .decode = cs_dppolicy_mirror_decode, .k = 1, .m = 0},
	{.name = "mirror", .encode = cs_dppolicy_mirror_encode, .decode = cs_dppolicy_mirror_decode, .k = 1, .m = 1},
};

#endif	/* DPPOLICY_H */

