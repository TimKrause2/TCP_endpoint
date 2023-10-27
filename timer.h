#include <signal.h>
#include <time.h>
#include <semaphore.h>

typedef struct timer timer;
typedef struct list_element list_element;
typedef struct cbl_element cbl_element;
typedef struct f_element f_element;

struct list_element
{
    timer *t;
    list_element *next;
    list_element *prev;
};

struct cbl_element
{
    timer *t;
    cbl_element *next;
};

struct f_element
{
    void *ptr;
    f_element *next;
};

struct timer{
    sem_t sem;
    int locked_out;
    long expire_second;
    void *arg;
    void (*expire_cb)(void *arg);
    list_element *le;
};

typedef struct timer timer;
int timer_init(void);

timer *timer_new( void (*expire_cb)(void *), void *arg);
void timer_destroy(timer *t);
void timer_lock(timer *t);
void timer_unlock(timer *t);
void timer_set(timer *t, int n_seconds);


