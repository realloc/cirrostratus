#ifndef CEPH_CRUSH_MAPPER_H
#define CEPH_CRUSH_MAPPER_H

/*
 * CRUSH functions for find rules and then mapping an input to an
 * output set.
 *
 * LGPL2
 */

#include "crush.h"

#define DEVICE_IN  0x10000
#define DEVICE_OUT 0
#define DEVICE_EXISTS 1

extern void float_weights_u32(float *weights, __u32 *u32_weight, unsigned size);
extern __u32 float_weight_u32(float w);
extern int block_to_osds(int replica_num, unsigned long long offset,int virtual_disk_id, sharelist *osds, float *weights);
extern int crush_find_rule(struct crush_map *map, int pool, int type, int size);
extern int crush_do_rule(struct crush_map *map,
			 int ruleno,
			 int x, int *result, int result_max,
			 int forcefeed,    /* -1 for none */
			 __u32 *weights);

#endif
