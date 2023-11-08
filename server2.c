#include "endpoint.h"
#include "util.h"
#define __USE_GNU
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
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
#include <time.h>

#define ENDPOINTS_MAX 10
#define LISTEN_BACKLOG 10
#define N_SEND_THREADS 2
#define N_RECV_THREADS 2
#define SOCKET_PATH "\0tims.server.socket"

struct timespec server_ts;

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
        if(le->e->peer_addr.ss_family!=AF_UNIX)
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

#define PACKETS_P_ENDPOINT 500000


void send_endpoint_list(endpoint *e)
{
    printf("send_endpoint_list: start\n");
    endpoint_list_lock();
    char *si_packet = packet_server_info_new(&server_ts, endpoint_count()*PACKETS_P_ENDPOINT);
    if(!si_packet){
        goto unlock_return;
    }
    s_ptr *si_sp = shared_ptr_new(si_packet);
    if(!si_sp){
        free(si_packet);
        goto unlock_return;
    }
    endpoint_send(e, si_sp);

    ele *le = el_head;
    while(le){
        endpoint *et = le->e;

        for(int i=0;i<PACKETS_P_ENDPOINT;i++)
        {
            char *ep_packet = packet_endpoint_info_new(
                        &et->peer_addr,
                        &et->init_ts,
                        et->send_sent,
                        et->recv_received,
                        et->recv_discarded);
            if(!ep_packet){
                continue;
            }
            s_ptr *ep_sp = shared_ptr_new(ep_packet);
            if(!ep_sp){
                free(ep_packet);
                continue;
            }
            endpoint_send(e, ep_sp);
        }
        le = le->next;
    }
unlock_return:
    endpoint_list_unlock();
    printf("send_endpoint_list: exiting\n");
}

void server_recv_unix_cb(void *packet, endpoint *e)
{
    if(packet_get_type(packet) == P_COMMAND
            && packet_get_code(packet) == P_CMD_CODE_ENDPOINT_LIST){
        send_endpoint_list(e);
    }
    free(packet);
}

void server_endpoint_new(int sfd)
{
    endpoint *e = endpoint_new(
                sfd,
                server_recv_cb, NULL, 0, 1);
    void *p;
    if(endpoint_count()>ENDPOINTS_MAX)
        p = packet_status_new(P_ST_CODE_BUSY);
    else
        p = packet_status_new(P_ST_CODE_READY);
    s_ptr *sp = shared_ptr_new(p);
    endpoint_send(e, sp);
}

void unix_endpoint_new(int sfd)
{
    endpoint *e = endpoint_new(
                sfd,
                server_recv_unix_cb, NULL, 0, 1);
}

typedef struct server_epoll_dispatch svr_ed;

struct server_epoll_dispatch
{
    int sfd;
    void (*endpoint_new)(int sfd);
};

int main( int argc, char *argv[] )
{
    int result;
    int r;

    r = clock_gettime(CLOCK_REALTIME, &server_ts);
    if(r==-1){
        perror("main: clock_gettime");
        printf("Couldn't get the server initialization time.\n");
    }

    if(!timer_init()){
        printf("Couldn't initialize the timer subsystem.\n");
        exit(1);
    }

    if(!endpoints_init(N_SEND_THREADS, N_RECV_THREADS)){
        printf("Couldn't initialize the endpoint subsystem.\n");
        exit(1);
    }

    int sfd;
	struct addrinfo hints;
	struct addrinfo *ai_res;
	struct addrinfo *ai_ptr;
	int N_l_sockets=0;
	struct sigaction sigact;

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

        svr_ed *ed = malloc(sizeof(svr_ed));
        if(!ed){
            perror("malloc(sizeof(svr_ed))");
            close(sfd);
            continue;
        }
        ed->sfd = sfd;
        ed->endpoint_new = server_endpoint_new;
        ev.data.ptr = ed;
		result = epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
		if(result==-1){
			perror("epoll_ctl");
			close(sfd);
			continue;
		}

		N_l_sockets++;
	}

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sfd==-1){
        perror("socket: AF_UNIX");
        exit(1);
    }

    struct sockaddr_un sa_server;

    socklen_t addr_len = sockaddr_un_prepare(&sa_server, SOCKET_PATH);
    result = bind(sfd, (struct sockaddr*)&sa_server, addr_len);
    if(result==-1){
        perror("bind: AF_UNIX");
        exit(1);
    }

    result = listen(sfd, LISTEN_BACKLOG);
    if(result==-1){
        perror("listen: AF_UNIX");
        exit(1);
    }

    svr_ed *ed = malloc(sizeof(svr_ed));
    if(!ed){
        perror("malloc(sizeof(svr_ed)): AF_UNIX");
        exit(1);
    }
    ed->sfd = sfd;
    ed->endpoint_new = unix_endpoint_new;
    ev.data.ptr = ed;
    result = epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
    if(result==-1){
        perror("epoll_ctl: AF_UNIX");
        exit(1);
    }

    N_l_sockets++;

    printf("N_l_sockets:%d\n", N_l_sockets);

	revents = malloc(sizeof(struct epoll_event)*N_l_sockets);
	if(!revents){
		perror("malloc");
		printf("Couldn't allocate memory for epoll events.");
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
                svr_ed *ed = revents[p].data.ptr;
                ed->endpoint_new(ed->sfd);
			}
		}
	}
}
