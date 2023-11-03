#include "fifo.h"
#include <stdlib.h>
#include <stdio.h>

fifo_t *fifo_new(int Nfifo)
{
    fifo_t *f = malloc(sizeof(fifo_t));
    if(!f){
        perror("fifo_new: malloc(fifo)");
        return NULL;
    }
    f->Nfifo = Nfifo;
    f->data = malloc(sizeof(void*)*Nfifo);
    if(!f->data){
        perror("fifo_new: malloc(data)");
        free(f);
        return NULL;
    }
    f->read_index = 0;
    f->read_avail = 0;
    f->write_index = 0;
    f->write_avail = Nfifo;
    f->locked_out = 0;
    int r = sem_init(&f->fifo_sem, 0, 1);
    if(r==-1){
        perror("fifo_new: sem_init");
        free(f->data);
        free(f);
        return NULL;
    }
    return f;
}

void *fifo_read_raw(fifo_t *f);

void fifo_delete(fifo_t *f)
{
    f->locked_out = 1;
    fifo_lock(f);
    int r = sem_destroy(&f->fifo_sem);
    if(r==-1){
        perror("fifo_delete: sem_destroy");
    }
    void *p;
    while(p=fifo_read_raw(f)){
        free(p);
    }
    free(f->data);
    free(f);
}

int fifo_write(fifo_t *f, void *p)
{
    printf("fifo_write:\n");
    if(f->locked_out) return 0;
    fifo_lock(f);
    if(!f->write_avail)
    {
        fifo_unlock(f);
        return 0;
    }
    f->data[f->write_index] = p;
    f->write_index++;
    f->write_index%=f->Nfifo;
    f->write_avail--;
    f->read_avail++;
    fifo_unlock(f);
    return 1;
}

void *fifo_read_raw(fifo_t *f)
{
    //printf("fifo_read_raw:\n");
    if(!f->read_avail) return NULL;
    void *p = f->data[f->read_index];
    f->read_index++;
    f->read_index%=f->Nfifo;
    f->read_avail--;
    f->write_avail++;
    return p;
}

void *fifo_read(fifo_t *f)
{
    if(f->locked_out) return NULL;
    fifo_lock(f);
    void *p = fifo_read_raw(f);
    fifo_unlock(f);
    return p;
}

void *fifo_peek(fifo_t *f)
{
    return f->data[f->read_index];
}

int fifo_empty(fifo_t *f)
{
    return f->read_avail==0?1:0;
}

int fifo_read_avail(fifo_t *f)
{
    return f->read_avail;
}

int fifo_write_avail(fifo_t *f)
{
    return f->write_avail;
}

void fifo_lock(fifo_t *f)
{
    int r = sem_wait(&f->fifo_sem);
    if(r==-1){
        perror("fifo_lock: sem_wait");
    }
}

void fifo_unlock(fifo_t *f)
{
    int r = sem_post(&f->fifo_sem);
    if(r==-1){
        perror("fifo_unlock: sem_post");
    }
}
