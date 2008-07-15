#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ggaoed.h"

#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

/**********************************************************************
 * Global variables
 */

/* Physical page size */
static long page_size;

/* Exponent of the page size */
static unsigned page_shift;

/* Valid packet sizes are between 1 (MTU=1500) and 4 (MTU=9000) pages */
static GTrashStack *caches[4];

/**********************************************************************
 * Functions
 */

void *alloc_packet(unsigned size)
{
	unsigned cache;
	void *ptr;
	int ret;

	cache = (size + page_size - 1) >> page_shift;
	size = cache-- << page_shift;

	if (G_UNLIKELY(cache > sizeof(caches) / sizeof(caches[0])))
	{
		/* Should not happen */
		logit(LOG_ERR, "Unexpected memory allocation size %u", size);
		return NULL;
	}

	ptr = g_trash_stack_pop(&caches[cache]);
	if (ptr)
		return ptr;

	ret = posix_memalign(&ptr, page_size, size);
	if (ret)
	{
		logit(LOG_ERR, "Memory allocation failed: %s", strerror(ret));
		return NULL;
	}
	return ptr;
}

void free_packet(void *buf, unsigned size)
{
	unsigned cache;

	cache = ((size + page_size - 1) >> page_shift) - 1;
	if (G_UNLIKELY(cache > sizeof(caches) / sizeof(caches[0])))
	{
		/* Should not happen */
		logit(LOG_ERR, "Unexpected memory de-allocation size %u", size);
		return;
	}

	g_trash_stack_push(&caches[cache], buf);
}

void mem_init(void)
{
	page_size = sysconf(_SC_PAGESIZE);
	for (page_shift = 0; 1l << page_shift < page_size; page_shift++)
		/* Nothing */;
}

void mem_done(void)
{
	unsigned i;
	void *p;

	for (i = 0; i < sizeof(caches) / sizeof(caches[0]); i++)
		while ((p = g_trash_stack_pop(&caches[i])))
			free(p);
}
