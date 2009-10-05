#ifndef UTIL_H
#define UTIL_H

#include <time.h>

#define NSEC_PER_SEC	1000000000

static inline void timespec_sub(const struct timespec *a,
	const struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (res->tv_nsec < 0)
	{
		res->tv_nsec += NSEC_PER_SEC;
		--res->tv_sec;
	}
}

static inline void timespec_add(const struct timespec *a,
	const struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_nsec = a->tv_nsec + b->tv_nsec;
	if (res->tv_nsec >= NSEC_PER_SEC)
	{
		res->tv_nsec -= NSEC_PER_SEC;
		++res->tv_sec;
	}
}

#endif /* UTIL_H */
