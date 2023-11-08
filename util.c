#include "util.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
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

void timespec_diff(struct timespec *t1, struct timespec *t0, struct timespec *r)
{
    r->tv_sec = t1->tv_sec - t0->tv_sec;
    r->tv_nsec = t1->tv_nsec - t0->tv_nsec;
    if(r->tv_nsec < 0){
        r->tv_sec--;
        r->tv_nsec += 1000000000;
    }
}

void print_elapsed(struct timespec *now, struct timespec *then)
{
    struct timespec diff;
    timespec_diff(now, then, &diff);
    long min = (diff.tv_sec / 60) % 60;
    long hrs = (diff.tv_sec / 3600) % 24;
    long days = diff.tv_sec / (3600*24);
    long sec = diff.tv_sec % 60;
    printf("%ld days %02ld hours %02ld minutes %02ld seconds %03ld milliseconds",
           days, hrs, min, sec, diff.tv_nsec/1000000);
}

void print_sockaddr(struct sockaddr_storage *ss)
{
    if(ss->ss_family==AF_INET){
        struct sockaddr_in *peer_addr = (struct sockaddr_in*)ss;
        printf("\tsin_port:%hu\n",ntohs( peer_addr->sin_port ) );
        printf("\tsin_addr:%s\n",inet_ntoa( peer_addr->sin_addr ) );
    }else if(ss->ss_family==AF_INET6){
        struct sockaddr_in6 *peer_addr = (struct sockaddr_in6*)ss;
        printf("\tsin6_port:%hu\n",ntohs(peer_addr->sin6_port));
        printf("\tsin6_addr:");
        for(int i=0;i<16;i++){
            printf("%02X",peer_addr->sin6_addr.s6_addr[i]);
            if(i%4 == 3 && i!=15){
                printf(":");
            }
        }
        printf("\n");
    }else if(ss->ss_family==AF_UNIX){
        printf("\tUNIX domain peer address.\n");
    }else{
        printf("\tAddress family not recognized.\n");
    }
}

size_t sockaddr_un_prepare(struct sockaddr_un *sa, char *path)
{
    memset(sa, 0, sizeof(struct sockaddr_un));
    sa->sun_family = AF_UNIX;
    if(*path == '\0'){
        *sa->sun_path = '\0';
        strncpy(sa->sun_path+1, path+1, sizeof(sa->sun_path)-2);
        size_t sun_path_bytes = strlen(path+1)+1;
        return offsetof(struct sockaddr_un,sun_path) + sun_path_bytes;

    }else{
        strncpy(sa->sun_path, path, sizeof(sa->sun_path)-1);
        return sizeof(struct sockaddr_un);
    }
}





