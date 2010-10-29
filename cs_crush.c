#include "ggaoed.h"
#include "ctl.h"
#include "util.h"

#include "ceph-client-standalone/crush/mapper.h"
#include "ceph-client-standalone/crush/crush.h"
#include "ceph-client-standalone/crush/hash.h"
#include "cs_crush.h"

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <sys/utsname.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>


#include <blkid/blkid.h>

void float_weights_32(float *weights, __u32 *u32_weights, int size)
{
    // TODO
    int i;
    if(weights == NULL) {
        for(i = 0; i < size; i++) {
            u32_weights[i] = 0x10000;
        }
    }
}

int block_to_nodes(int replica_num, unsigned long long offset,
				int virtual_disk_id, int *osds, float *weights)
{
    __u32 u32_weights[1];

    float_weights_32(weights, &u32_weights[0], 1); //alpha version, we have only 1 device

    // map to osds[]
    int x = crush_hash32_2(CRUSH_HASH_RJENKINS1, offset, virtual_disk_id);  // hash must be from block

    // what crush rule?
    int ruleno = crush_find_rule(map, 1, 1/*replicated*/, replica_num); //Alfa version!! We have only one rule with 0 ruleset and type = replicated
    if (ruleno >= 0) {
      return crush_do_rule(map, ruleno, x/*parametrization on hash*/, osds/*output*/,
              replica_num/*max size of outputs*/, -1/*maybe will work =)*/, u32_weights);
    }
}

/*
 * decode crush map
 */
static int crush_decode_uniform_bucket(void **p, void *end,
				       struct crush_bucket_uniform *b)
{
	printf("crush_decode_uniform_bucket %p to %p\n", *p, end);
	ceph_decode_need(p, end, (1+b->h.size) * sizeof(__u32), bad);
	b->item_weight = ceph_decode_32(p);
	return 0;
bad:
	return -EINVAL;
}

static int crush_decode_list_bucket(void **p, void *end,
				    struct crush_bucket_list *b)
{
	int j;
	printf("crush_decode_list_bucket %p to %p\n", *p, end);
	b->item_weights = calloc(b->h.size, sizeof(__u32));
	if (b->item_weights == NULL)
		return -ENOMEM;
	b->sum_weights = calloc(b->h.size, sizeof(__u32));
	if (b->sum_weights == NULL)
		return -ENOMEM;
	ceph_decode_need(p, end, 2 * b->h.size * sizeof(__u32), bad);
	for (j = 0; j < b->h.size; j++) {
		b->item_weights[j] = ceph_decode_32(p);
		b->sum_weights[j] = ceph_decode_32(p);
	}
	return 0;
bad:
	return -EINVAL;
}

static int crush_decode_tree_bucket(void **p, void *end,
				    struct crush_bucket_tree *b)
{
	int j;
	printf("crush_decode_tree_bucket %p to %p\n", *p, end);
	ceph_decode_32_safe(p, end, b->num_nodes, bad);
	b->node_weights = calloc(b->num_nodes, sizeof(__u32));
	if (b->node_weights == NULL)
		return -ENOMEM;
	ceph_decode_need(p, end, b->num_nodes * sizeof(__u32), bad);
	for (j = 0; j < b->num_nodes; j++)
		b->node_weights[j] = ceph_decode_32(p);
	return 0;
bad:
	return -EINVAL;
}

static int crush_decode_straw_bucket(void **p, void *end,
				     struct crush_bucket_straw *b)
{
	int j;
	printf("crush_decode_straw_bucket %p to %p\n", *p, end);
	b->item_weights = calloc(b->h.size, sizeof(__u32));
	if (b->item_weights == NULL)
		return -ENOMEM;
	b->straws = calloc(b->h.size, sizeof(__u32));
	if (b->straws == NULL)
		return -ENOMEM;
	ceph_decode_need(p, end, 2 * b->h.size * sizeof(__u32), bad);
	for (j = 0; j < b->h.size; j++) {
		b->item_weights[j] = ceph_decode_32(p);
		b->straws[j] = ceph_decode_32(p);
	}
	return 0;
bad:
	return -EINVAL;
}
struct crush_map *crush_decode(void *pbyval, void *end)
{
	struct crush_map *c;
	int err = -EINVAL;
	int i, j;
	void **p = &pbyval;
	void *start = pbyval;
	__u32 magic;

	printf("crush_decode %p to %p len %d\n", *p, end, (int)(end - *p));

	c = malloc(sizeof(*c));
	if (c == NULL)
		return -ENOMEM;

	ceph_decode_need(p, end, 4*sizeof(__u32), bad);
	magic = ceph_decode_32(p);
	if (magic != CRUSH_MAGIC) {
		printf("crush_decode magic %x != current %x\n",
		       (unsigned)magic, (unsigned)CRUSH_MAGIC);
		goto bad;
	}
	c->max_buckets = ceph_decode_32(p);
	c->max_rules = ceph_decode_32(p);
	c->max_devices = ceph_decode_32(p);

	c->device_parents = calloc(c->max_devices, sizeof(__u32));
	if (c->device_parents == NULL)
		goto badmem;
	c->bucket_parents = calloc(c->max_buckets, sizeof(__u32));
	if (c->bucket_parents == NULL)
		goto badmem;

	c->buckets = calloc(c->max_buckets, sizeof(*c->buckets));
	if (c->buckets == NULL)
		goto badmem;
	c->rules = calloc(c->max_rules, sizeof(*c->rules));
	if (c->rules == NULL)
		goto badmem;

	/* buckets */
	for (i = 0; i < c->max_buckets; i++) {
		int size = 0;
		__u32 alg;
		struct crush_bucket *b;

		ceph_decode_32_safe(p, end, alg, bad);
		if (alg == 0) {
			c->buckets[i] = NULL;
			continue;
		}
		printf("crush_decode bucket %d off %x %p to %p\n",
		     i, (int)(*p-start), *p, end);

		switch (alg) {
		case CRUSH_BUCKET_UNIFORM:
			size = sizeof(struct crush_bucket_uniform);
			break;
		case CRUSH_BUCKET_LIST:
			size = sizeof(struct crush_bucket_list);
			break;
		case CRUSH_BUCKET_TREE:
			size = sizeof(struct crush_bucket_tree);
			break;
		case CRUSH_BUCKET_STRAW:
			size = sizeof(struct crush_bucket_straw);
			break;
		default:
			err = -EINVAL;
			goto bad;
		}
//		BUG_ON(size == 0);
		b = c->buckets[i] = malloc(size);
		if (b == NULL)
			goto badmem;

		ceph_decode_need(p, end, 4*sizeof(__u32), bad);
		b->id = ceph_decode_32(p);
		b->type = ceph_decode_16(p);
		b->alg = ceph_decode_8(p);
		b->hash = ceph_decode_8(p);
		b->weight = ceph_decode_32(p);
		b->size = ceph_decode_32(p);

		printf("crush_decode bucket size %d off %x %p to %p\n",
		     b->size, (int)(*p-start), *p, end);

		b->items = calloc(b->size, sizeof(__s32));
		if (b->items == NULL)
			goto badmem;
		b->perm = calloc(b->size, sizeof(__u32));
		if (b->perm == NULL)
			goto badmem;
		b->perm_n = 0;

		ceph_decode_need(p, end, b->size*sizeof(__u32), bad);
		for (j = 0; j < b->size; j++)
			b->items[j] = ceph_decode_32(p);

		switch (b->alg) {
		case CRUSH_BUCKET_UNIFORM:
			err = crush_decode_uniform_bucket(p, end,
				  (struct crush_bucket_uniform *)b);
			if (err < 0)
				goto bad;
			break;
		case CRUSH_BUCKET_LIST:
			err = crush_decode_list_bucket(p, end,
			       (struct crush_bucket_list *)b);
			if (err < 0)
				goto bad;
			break;
		case CRUSH_BUCKET_TREE:
			err = crush_decode_tree_bucket(p, end,
				(struct crush_bucket_tree *)b);
			if (err < 0)
				goto bad;
			break;
		case CRUSH_BUCKET_STRAW:
			err = crush_decode_straw_bucket(p, end,
				(struct crush_bucket_straw *)b);
                        if (err < 0)
				goto bad;
			break;
		}
	}

	/* rules */
	printf("rule vec is %p\n", c->rules);
	for (i = 0; i < c->max_rules; i++) {
		__u32 yes;
		struct crush_rule *r;

		ceph_decode_32_safe(p, end, yes, bad);
		if (!yes) {
			printf("crush_decode NO rule %d off %x %p to %p\n",
			     i, (int)(*p-start), *p, end);
			c->rules[i] = NULL;
			continue;
		}

		printf("crush_decode rule %d off %x %p to %p\n",
		     i, (int)(*p-start), *p, end);

		/* len */
		ceph_decode_32_safe(p, end, yes, bad);
#if BITS_PER_LONG == 32
		err = -EINVAL;
		if (yes > ULONG_MAX / sizeof(struct crush_rule_step))
			goto bad;
#endif
		r = c->rules[i] = malloc(sizeof(*r) +
					  yes*sizeof(struct crush_rule_step));
		if (r == NULL)
			goto badmem;
		printf(" rule %d is at %p\n", i, r);
		r->len = yes;
		ceph_decode_copy_safe(p, end, &r->mask, 4, bad); /* 4 u8's */
		ceph_decode_need(p, end, r->len*3*sizeof(__u32), bad);
		for (j = 0; j < r->len; j++) {
			r->steps[j].op = ceph_decode_32(p);
			r->steps[j].arg1 = ceph_decode_32(p);
			r->steps[j].arg2 = ceph_decode_32(p);
		}
	}

	/* ignore trailing name maps. */

	printf("crush_decode success\n");
	return c;

badmem:
	err = -ENOMEM;
bad:
	printf("crush_decode fail %d\n", err);
//	crush_destroy(c);
	return err;
}