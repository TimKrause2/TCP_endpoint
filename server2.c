#include "endpoint.h"
#define __USE_GNU
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <semaphore.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>

#define ENDPOINTS_MAX 10
#define LISTEN_BACKLOG 10
#define N_SEND_THREADS 2
#define N_RECV_THREADS 2

struct shm_data
{
	sem_t sem;
	int N_children;
};

void process_packet_status(char *packet){
    switch(packet_get_code(packet)){
	case P_ST_CODE_READY:
		break;
	case P_ST_CODE_BUSY:

		break;
	case P_ST_CODE_CONFIRM:
        printf("Confirm packet status.\n");
		break;
	}
    free(packet);
}

typedef struct endpoint_send_element ese;

struct endpoint_send_element
{
    endpoint *e;
    ese *next;
};

ese *es_head = NULL;
ese *es_tail = NULL;

ese *es_new(endpoint *e)
{
    ese *es = malloc(sizeof(ese));
    if(!es)
        return NULL;
    es->e = e;
    if(!es_head){
        es_head = es;
        es_tail = es;
        es->next = NULL;
    }else{
        es_tail->next = es;
        es_tail = es;
        es->next = NULL;
    }
    return es;
}

void es_call(s_ptr *sp)
{
    ese *es = es_head;
    while(es){
        endpoint_send(es->e, sp);
        ese *esf = es;
        es = es->next;
        free(esf);
    }
    es_head = NULL;
    es_tail = NULL;
}

void process_packet_data(char *pd)
{
    int nbytes = packet_data_get_nbytes(pd);
    printf("data packet: nbytes:%d\n",nbytes);
    char *data = (char*)packet_data_get_data(pd);
    if(nbytes>8)nbytes=8;
	for(int b=0;b<nbytes;b++){
        printf("%02hhX",data[b]);
	}
	printf("\n");
    //free(pd);
    //return;

    // broadcast to all endpoints
    s_ptr *sp = shared_ptr_new(pd);
    if(!sp){
        printf("packet dropped.\n");
        free(pd);
        return;
    }
    endpoint_list_lock();
    ele *le = el_head;
    while(le){
        endpoint_send(le->e, shared_ptr_alloc(sp));
        le = le->next;
    }
    endpoint_list_unlock();
    shared_ptr_free(sp);
}

void process_packet(char *p){
    switch(packet_get_type(p)){
	case P_STATUS:
        process_packet_status(p);
		break;
	case P_DATA:
        process_packet_data(p);
		break;
	}
}

void server_recv_cb(void *packet, endpoint *e)
{
    //printf("server_recv_cb: packet=0x%p\n", packet);
    process_packet(packet);
}

int main( int argc, char *argv[] )
{
    if(!timer_init()){
        printf("Couldn't initialize the timer subsystem.\n");
        exit(1);
    }

    if(!endpoints_init(N_SEND_THREADS, N_RECV_THREADS)){
        printf("Couldn't initialize the endpoint subsystem.\n");
        exit(1);
    }

    int sfd;
	int result;
	struct addrinfo hints;
	struct addrinfo *ai_res;
	struct addrinfo *ai_ptr;
	int N_l_sockets=0;
	struct pollfd *pollfds;
	struct sigaction sigact;

	sigact.sa_handler = SIG_IGN;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_NOCLDWAIT;
	sigact.sa_restorer = NULL;

	result = sigaction(SIGCHLD, &sigact, NULL);
	if(result<0){
		perror("sigaction");
		exit(1);
	}

	if( argc < 2 ){
		printf("Usage:%s <service or port>\n",argv[0]);
		exit( 1 );
	}
	
	memset( &hints, 0, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags |= AI_PASSIVE;
	
	result = getaddrinfo( NULL, argv[1], &hints, &ai_res );
	if( result ){
		printf("getaddrinfo error:%s\n",gai_strerror( result ) );
		exit( 1 );
	}

	int epfd = epoll_create1(0);
	if(epfd==-1){
		perror("epoll_create1(0)");
		exit(1);
	}
	struct epoll_event *revents;
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;

	for(ai_ptr = ai_res;ai_ptr;ai_ptr = ai_ptr->ai_next) {
		sfd = socket( ai_ptr->ai_family,
					  ai_ptr->ai_socktype | SOCK_NONBLOCK,
					  ai_ptr->ai_protocol );
		if( sfd == -1 ){
			perror( "socket" );
			continue;
		}

		int reuseport=1;
		setsockopt(sfd,SOL_SOCKET,SO_REUSEPORT,&reuseport,sizeof(int));

		result = bind( sfd, ai_ptr->ai_addr, ai_ptr->ai_addrlen );
		if( result == -1 ){
			perror( "bind" );
			close(sfd);
			continue;
		}

		result = listen( sfd, LISTEN_BACKLOG );
		if( result == -1 ){
			perror( "listen" );
			close(sfd);
			continue;
		}

		ev.data.fd = sfd;
		result = epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
		if(result==-1){
			perror("epoll_ctl");
			close(sfd);
			continue;
		}

		N_l_sockets++;
	}
	
	revents = malloc(sizeof(struct epoll_event)*N_l_sockets);
	if(!revents){
		perror("malloc");
		printf("Couldn't allocate memory for epoll events.");
		exit(1);
	}


	int pipefd[2];
	int r;
	r = pipe(pipefd);
	if(r<0){
		perror("pipe");
		exit(1);
	}

	srand48(0);

	struct shm_data *shm_data = mmap(NULL, sizeof(struct shm_data),
									 PROT_READ | PROT_WRITE,
									 MAP_SHARED | MAP_ANONYMOUS,
									 -1, 0);
	if(shm_data==MAP_FAILED){
		perror("mmap");
		exit(1);
	}

	shm_data->N_children = 0;
	r = sem_init(&shm_data->sem, 1, 1);
	if(r<0){
		perror("sem_init");
		exit(1);
	}

	while(1){
		printf("starting poll\n");
		r = epoll_wait(epfd, revents, N_l_sockets, -1);
		if(r==-1){
			perror("epoll_wait");
			continue;
		}
		printf("r:%d\n",r);
		for(int p=0;p<r;p++){
			if(revents[p].events&EPOLLIN){
                endpoint *e = endpoint_new(
                            revents[p].data.fd,
                            server_recv_cb, NULL, 0, 1);
                void *p;
                int e_terminate = 0;
                if(endpoint_count()>ENDPOINTS_MAX)
                    p = packet_status_new(P_ST_CODE_BUSY);
                else
                    p = packet_status_new(P_ST_CODE_READY);
                s_ptr *sp = shared_ptr_new(p);
                endpoint_send(e, sp);
			}
		}
	}
}
