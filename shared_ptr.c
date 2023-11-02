#include "shared_ptr.h"
#include <stdlib.h>
#include <stdio.h>

s_ptr *shared_ptr_new(void *data)
{
    s_ptr *p = malloc(sizeof(s_ptr));
    if(!p){
        perror("shared_ptr_new: malloc");
        return NULL;
    }
    int r = sem_init(&p->sem, 0, 1);
    if(r==-1) {
        perror("shared_ptr_new: sem_init");
        free(p);
        return NULL;
    }
    p->N_ref = 1;
    p->data = data;
    //printf("shared_ptr_new: p:%p data:%p\n", p, data);
    return p;
}

s_ptr *shared_ptr_alloc(s_ptr *p)
{
    sem_wait(&p->sem);
    p->N_ref++;
    sem_post(&p->sem);
    return p;
}

void shared_ptr_free(s_ptr *p)
{
    sem_wait(&p->sem);
    p->N_ref--;
    if(!p->N_ref){
        //printf("shared_ptr_free: p:%p data:%p\n",p, p->data);
        sem_destroy(&p->sem);
        free(p->data);
        free(p);
        return;
    }
    sem_post(&p->sem);
}

void *shared_ptr_data(s_ptr *p)
{
    return p->data;
}
