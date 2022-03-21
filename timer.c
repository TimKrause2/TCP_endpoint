#include <signal.h>
#include <time.h>
#include <string.h>
#include "timer.h"

int timer_init(timer *t, void (*cbfunc)(union sigval), union sigval arg)
{
	struct sigevent se;
	memset(&se,0,sizeof(se));
	se.sigev_notify = SIGEV_THREAD;
	se.sigev_notify_function = cbfunc;
	se.sigev_value = arg;
	se.sigev_notify_attributes = NULL;

	int r = timer_create(CLOCK_MONOTONIC, &se, &t->timerid);
	return r;
}

int timer_set(timer *t, int n_seconds)
{
	struct itimerspec ts;
	memset(&ts,0,sizeof(ts));
	ts.it_value.tv_sec = n_seconds;

	int r = timer_settime(t->timerid, 0, &ts, NULL);
	return r;
}


