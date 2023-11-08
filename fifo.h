#include <semaphore.h>

struct fifo
{
    int Nfifo;
    void **data;
    int read_index;
    int read_avail;
    int write_index;
    int write_avail;
    sem_t fifo_sem;
    sem_t write_sem;
    int locked_out;
};

typedef struct fifo fifo_t;

fifo_t *fifo_new(int Nfifo);
void fifo_delete(fifo_t *f);
int fifo_write(fifo_t *f, void *p);
void* fifo_read(fifo_t *f);
void* fifo_peek(fifo_t *f);
int fifo_empty(fifo_t *f);
int fifo_read_avail(fifo_t *f);
int fifo_write_avail(fifo_t *f);
void fifo_lock(fifo_t *f);
void fifo_unlock(fifo_t *f);
