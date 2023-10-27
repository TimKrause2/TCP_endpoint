#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "timer.h"

list_element *le_head = NULL;
list_element *le_pending = NULL;
sem_t list_sem;
cbl_element *cbl_head = NULL;
cbl_element *cbl_tail = NULL;
sem_t free_sem;
f_element *f_head = NULL;
f_element *f_tail = NULL;
long current_second=0;

void free_list_lock(void)
{
    sem_wait(&free_sem);
}

void free_list_unlock(void)
{
    sem_post(&free_sem);
}

void free_list_free(void *p)
{
    f_element *f = malloc(sizeof(f_element));
    if(!f){
        perror("f_list_free: malloc");
        return;
    }
    free_list_lock();
    f->ptr = p;
    f->next = NULL;
    if(f_head == NULL){
        f_head = f;
        f_tail = f;
    }else{
        f_tail->next = f;
        f_tail = f;
    }
    free_list_unlock();
}

void free_list_purge(void)
{
    free_list_lock();
    f_element *f = f_head;
    while(f){
        printf("freeing... ptr:0x%p\n", f->ptr);
        free(f->ptr);
        f_element *ff = f;
        f = f->next;
        free(ff);
    }
    f_head = NULL;
    f_tail = NULL;
    free_list_unlock();
}

void cbl_add_timer(timer *t)
{
    cbl_element *e = malloc(sizeof(cbl_element));
    if(!e){
        perror("cbl_add_timer: malloc");
        return;
    }
    e->t = t;
    e->next = NULL;
    if(cbl_head == NULL){
        cbl_head = e;
        cbl_tail = e;
    }else{
        cbl_tail->next = e;
        cbl_tail = e;
    }
}

void cbl_call(void){
    cbl_element *e = cbl_head;
    while(e){
        if(!e->t->locked_out)
            e->t->expire_cb(e->t->arg);
        cbl_element *ef = e;
        e = e->next;
        free(ef);
    }
    cbl_head = NULL;
    cbl_tail = NULL;
}

void list_elements_lock(void)
{
    sem_wait(&list_sem);
}

void list_elements_unlock(void)
{
    sem_post(&list_sem);
}

void list_element_sort(list_element *le);

void list_element_push(list_element *le)
{
    list_elements_lock();
    if(le_head == NULL){
        le_head = le;
        le->next = NULL;
        le->prev = NULL;
    }else{
        le->next = le_head;
        le->prev = NULL;
        le_head->prev = le;
        le_head = le;
        list_element_sort(le);
    }
    list_elements_unlock();
}

void list_element_remove(list_element *le)
{
    if(le_head == le){
        le_head = le->next;
        le_head->prev = NULL;
    }else{
        le->prev->next = le->next;
        if(le->next){
            le->next->prev = le->prev;
        }
    }
    if(le_pending==le){
        le_pending = le_pending->next;
    }
}

void list_element_insert(list_element *le, list_element *le_at)
{
    if(le_at == le_head){
        le_at->prev = le;
        le_head = le;
        le->prev = NULL;
        le->next = le_at;
    }else{
        le_at->prev->next = le;
        le->prev = le_at->prev;
        le_at->prev = le;
        le->next = le_at;
    }
}

void list_element_sort(list_element *le)
{
    list_element *le_rest = le->next;
    if(le_rest){
        while(le_rest->t->expire_second<le->t->expire_second){
            if(le_rest->next==NULL){
                list_element_remove(le);
                le_rest->next = le;
                le->prev = le_rest;
                le->next = NULL;
                return;
            }else{
                le_rest = le_rest->next;
            }
        }
        list_element_remove(le);
        list_element_insert(le, le_rest);
        return;
    }
}

void list_element_delete(list_element *le)
{
    list_elements_lock();
    list_element_remove(le);
    list_elements_unlock();
    free(le);
}

list_element *list_element_new(timer *t)
{
    list_element *le = malloc(sizeof(list_element));
    if(!le){
        perror("list_element_new: malloc");
        return NULL;
    }
    le->t = t;
    le->next = NULL;
    le->prev = NULL;
    list_element_push(le);
    return le;
}

timer *timer_new( void (*expire_cb)(void *), void *arg)
{
    timer *t = malloc(sizeof(timer));
    if(!t){
        perror("timer_create: malloc");
        return NULL;
    }
    t->expire_second = current_second;
    t->locked_out = 0;
    t->expire_cb = expire_cb;
    t->arg = arg;
    t->le = list_element_new(t);
    if(!t->le){
        free(t);
        return NULL;
    }
    int r = sem_init(&t->sem, 0, 1);
    if(r==-1){
        perror("timer_create: sem_init");
        list_element_delete(t->le);
        free(t);
        return NULL;
    }
    return t;
}

void timer_destroy(timer *t)
{
    t->locked_out = 1;
    timer_lock(t);
    list_element_delete(t->le);
    int r = sem_destroy(&t->sem);
    if(r==-1){
        perror("timer_destroy: sem_destroy");
    }
    free_list_free(t);
}

void timer_lock(timer *t)
{
    sem_wait(&t->sem);
}

void timer_unlock(timer *t)
{
    sem_post(&t->sem);
}

void timer_set(timer *t, int n_seconds)
{
    if(t->locked_out) return;
    timer_lock(t);
    t->expire_second = current_second + n_seconds;
    list_elements_lock();
    list_element_sort(t->le);
    list_elements_unlock();
    timer_unlock(t);
}

timer_t main_timerid;

void timer_update_cb(union sigval arg)
{
    current_second++;
    list_elements_lock();
    list_element *le = le_head;
    while(le && le->t->expire_second<current_second){
        le = le->next;
    }
    le_pending = le;

    while(le_pending && le_pending->t->expire_second == current_second){
        if(!le_pending->t->locked_out)
            cbl_add_timer(le_pending->t);
        le_pending = le_pending->next;
    }

    list_elements_unlock();
    cbl_call();
    free_list_purge();
}

int timer_init()
{
    int r;
    r = sem_init(&list_sem, 0, 1);
    if(r==-1){
        perror("timer_init: sem_init(list_sem)");
        return 0;
    }
    r = sem_init(&free_sem, 0, 1);
    if(r==-1){
        perror("timer_init: sem_init(free_sem)");
        return 0;
    }
    struct sigevent se;
	memset(&se,0,sizeof(se));
	se.sigev_notify = SIGEV_THREAD;
    se.sigev_notify_function = timer_update_cb;
    se.sigev_value.sival_ptr = NULL;
	se.sigev_notify_attributes = NULL;

    r = timer_create(CLOCK_MONOTONIC, &se, &main_timerid);
    if(r==-1){
        perror("timer_init: timer_create");
        return 0;
    }

    struct itimerspec ts;
    memset(&ts,0,sizeof(ts));
    ts.it_value.tv_sec = 1;
    ts.it_interval.tv_sec = 1;

    r = timer_settime(main_timerid, 0, &ts, NULL);
    if(r==-1){
        perror("timer_init: timer_settime");
        return 0;
    }
    return 1;
}


