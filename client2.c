#include "endpoint.h"
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

void process_packet_status(struct packet_status *ps, endpoint *e){
	switch(ps->header.code){
	case P_ST_CODE_READY:
		break;
	case P_ST_CODE_BUSY:
		printf("server is busy\n");
        exit(0);
		break;
	case P_ST_CODE_CONFIRM:
        printf("Confirm packet status.\n");
		break;
	}
}

void process_packet_data(struct packet_data *pd, endpoint *e){
	int nbytes = pd->header.length - sizeof(struct packet_common);
	printf("data packet: nbytes:%d\n", nbytes);
	if(nbytes>8)nbytes=8;
	for(int b=0;b<nbytes;b++){
		printf("%02hhX",pd->data[b]);
	}
	printf("\n");
}

void process_packet(char *p, endpoint *e){
	struct packet_common *header = (struct packet_common *)p;
	switch(header->type){
	case P_STATUS:
		process_packet_status((struct packet_status*)p, e);
		break;
	case P_DATA:
		process_packet_data((struct packet_data*)p, e);
		break;
	}
	free(p);
}


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

void client_recv_cb(void *packet, endpoint *e)
{
    client *c = e->recv_cb_arg;
    switch(c->state){
    case C_STATE_R_STATUS:
        process_packet(packet, e);
        c->state = C_STATE_RECEIVE;
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
	
	result = getaddrinfo( argv[1], argv[2], &hints, &addrinfo_res );
	if( result != 0 ){
		printf("hostname lookup failed: %s\n", gai_strerror( result ) );
		exit( 1 );
	}
	
	sfd = socket( addrinfo_res->ai_family,
				  addrinfo_res->ai_socktype,
				  addrinfo_res->ai_protocol );
	if( sfd == -1 ){
		perror( "socket" );
		exit( 1 );
	}
	
	result = connect( sfd, (const struct sockaddr*)addrinfo_res->ai_addr, addrinfo_res->ai_addrlen );
	if( result == -1 ){
		perror( "connect" );
		exit( 1 );
	}

	int flags = fcntl(sfd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(sfd, F_SETFL, flags);


	printf("connection established\n");

    client c;
    c.state = C_STATE_R_STATUS;
    endpoint_new(sfd, client_recv_cb, (void*)&c, 0, 0);

    while(endpoint_count()) {
        sleep(1);
    }
	
	return 0;
}
	
	
	
	
