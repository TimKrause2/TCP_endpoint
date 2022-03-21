#include <signal.h>
#include <time.h>

struct timer{
	timer_t timerid;
};

typedef struct timer timer;
/*
 * return code
 * 0 success
 * -1 error and errno is set
 */
int timer_init(timer *t, void (*cbfunc)(union sigval), union sigval arg);
int timer_set(timer *t, int n_seconds);


