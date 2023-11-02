#include "util.h"
#include <time.h>
#include <stdlib.h>
#include <math.h>

void random_init(void)
{
    struct timespec ct;
    clock_gettime(CLOCK_REALTIME, &ct);
    srand48(ct.tv_nsec);
}


int random_range(int lo, int hi)
{
    int delta = hi - lo;
    int r = (int)floor(drand48()*delta);
    return lo + r;
}

void millisleep(int milli_seconds)
{
    long nano_seconds = (long)milli_seconds*1000000;
    long seconds = nano_seconds / 1000000000;
    nano_seconds %= 1000000000;

    struct timespec ts;
    ts.tv_sec = seconds;
    ts.tv_nsec = nano_seconds;
    nanosleep(&ts, NULL);
}
