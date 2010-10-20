#include "dppolicy.h"

#include <stdlib.h>

static struct cs_netlist* cs_dppolicy_mirror_encode(struct queue_item *q)
{
	struct device *const dev = q->dev;

        struct cs_netlist *nl_item;
        if ((nl_item = malloc(sizeof(struct cs_netlist))) == NULL)
            return NULL;

        nl_item->buf = q->buf;
        nl_item->length = q->length;
        nl_item->count = dev->dppolicy.k + dev->dppolicy.m;

        //memcpy(nl_item->wwn, dev->cfg.wwn, WWN_ALEN);
        /* TODO:
         * nl_item->offset += nl_item->length;
         * if we have a blocks
         */
        nl_item->offset = q->offset;

        nl_item->writebit = q->is_write;
        
        nl_item->next = NULL;

	return nl_item;
}

static int cs_dppolicy_mirror_decode(struct queue_item *q, struct cs_netlist *nl)
{
        q->buf = nl->buf;
        q->length = nl->length;
        
        nl->buf = NULL;
	nl->length = 0;

	return 0;
}