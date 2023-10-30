#include <semaphore.h>

typedef struct shared_ptr s_ptr;

struct shared_ptr
{
    sem_t sem;
    void *data;
    int  N_ref;
};

s_ptr *shared_ptr_new(void *data);
s_ptr *shared_ptr_alloc(s_ptr *p);
void shared_ptr_free(s_ptr *p);
void *shared_ptr_data(s_ptr *p);
