#include "endpoint.h"
#include "util.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#define N_BYTES_MIN 16*1024*1024
#define N_BYTES_MAX 32*1024*1024
#define SLEEP_MS_MIN 2000
#define SLEEP_MS_MAX 4000

struct client_s
{
    int state;
};

typedef struct client_s client;

enum {
    C_STATE_R_STATUS,
    C_STATE_RECEIVE,
    C_STATE_QUIT
};

client c;

void process_packet_status(char *ps, endpoint *e){
    //printf("process_packet_status:\n");
    switch(packet_get_code(ps)){
	case P_ST_CODE_READY:
        c.state = C_STATE_RECEIVE;
		break;
	case P_ST_CODE_BUSY:
		printf("server is busy\n");
        c.state = C_STATE_QUIT;
        endpoint_close(e);
		break;
	case P_ST_CODE_CONFIRM:
        printf("Confirm packet status.\n");
		break;
	}
}

void process_packet_data(char *pd, endpoint *e){
    //printf("process_packet_data:\n");
    int nbytes = packet_data_get_nbytes(pd);
	printf("data packet: nbytes:%d\n", nbytes);
    char *data = packet_data_get_data(pd);
	if(nbytes>8)nbytes=8;
	for(int b=0;b<nbytes;b++){
        printf("%02hhX",data[b]);
	}
	printf("\n");
}

void process_packet(char *p, endpoint *e){
    switch(packet_get_type(p)){
	case P_STATUS:
        process_packet_status(p, e);
		break;
	case P_DATA:
        process_packet_data(p, e);
		break;
	}
	free(p);
}


void client_recv_cb(void *packet, endpoint *e)
{
    //printf("client_recv_cb: packet:%p\n", packet);
    switch(c.state){
    case C_STATE_R_STATUS:
        process_packet(packet, e);
        break;
    case C_STATE_RECEIVE:
        process_packet(packet, e);
        break;
    default:
        break;
    }
}

int main( int argc, char *argv[] )
{
    if(!timer_init()){
        printf("Couldn't initialize timer system.\n");
        exit(1);
    }

    if(!endpoints_init(1,1)){
        printf("Couldn't initialize the endpoint subsystem.\n");
        exit(1);
    }

    random_init();

    int sfd;
	int result;
	struct addrinfo hints;
	struct addrinfo *addrinfo_res;
	
	if( argc < 3 ){
		printf("Usage:\n%s <hostname> <service or port>\n", argv[0] );
		exit( 1 );
	}
	
	memset( &hints, 0, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    printf("client2 main: calling getaddrinfo.\n");
	result = getaddrinfo( argv[1], argv[2], &hints, &addrinfo_res );
	if( result != 0 ){
		printf("hostname lookup failed: %s\n", gai_strerror( result ) );
		exit( 1 );
	}
    printf("client2 main: getaddrinfo returned. calling socket\n");
	sfd = socket( addrinfo_res->ai_family,
				  addrinfo_res->ai_socktype,
				  addrinfo_res->ai_protocol );
	if( sfd == -1 ){
		perror( "socket" );
		exit( 1 );
	}
    printf("client2 main: socket returned. calling connect.\n");
	result = connect( sfd, (const struct sockaddr*)addrinfo_res->ai_addr, addrinfo_res->ai_addrlen );
	if( result == -1 ){
		perror( "connect" );
		exit( 1 );
	}

	int flags = fcntl(sfd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(sfd, F_SETFL, flags);


	printf("connection established\n");

    c.state = C_STATE_R_STATUS;
    endpoint_new(sfd, client_recv_cb, (void*)&c, 0, 0);
    int tests = 10;
    while(c.state == C_STATE_R_STATUS && tests )
    {
        tests--;
        millisleep(100);
    }
    if(c.state == C_STATE_R_STATUS){
        printf("Didn't receive server connection status.\n");
        exit(1);
    }
    if(c.state == C_STATE_QUIT){
        printf("Server is busy.\n");
        exit(1);
    }
    int do_loop = 1;
    while(do_loop) {
        int nbytes = random_range(N_BYTES_MIN, N_BYTES_MAX);
        void *data = malloc(nbytes);
        if(!data){
            perror("client2 main: malloc");
            continue;
        }


        void *packet = packet_data_new(data, nbytes);
        free(data);
        if(!packet){
            printf("client2 main: couldn't get a new data packet.\n");
            continue;
        }
        printf("client2 main: new packet nbytes=%d\n", nbytes);
        s_ptr *sp = shared_ptr_new(packet);
        if(!sp){
            printf("client2 main: couldn't get a shared pointer.\n");
            free(packet);
            continue;
        }
        shared_ptr_alloc(sp);
        endpoint_list_lock();
        if(el_head){
            //printf("client2 main: calling endpoint_send\n");
            endpoint_send(el_head->e, sp);
            //printf("client2 main: calling endpoint_send a second time.\n");
            endpoint_send(el_head->e, sp);
            //printf("client2 main: endpoint_send returned.\n");
        }else{
            shared_ptr_free(sp);
            shared_ptr_free(sp);
            do_loop = 0;
        }
        endpoint_list_unlock();
        millisleep(random_range(SLEEP_MS_MIN, SLEEP_MS_MAX));
    }
	
	return 0;
}
