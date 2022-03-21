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

void process_packet_status(struct packet_status *ps, endpoint_t *e){
	switch(ps->header.code){
	case P_ST_CODE_READY:
		break;
	case P_ST_CODE_BUSY:
		printf("server is busy\n");
		io_shutdown(e);
		break;
	case P_ST_CODE_CONFIRM:
		break;
	}
}

void process_packet_data(struct packet_data *pd, endpoint_t *e){
	int nbytes = pd->header.length - sizeof(struct packet_common);
	printf("data packet: nbytes:%d\n", nbytes);
	if(nbytes>8)nbytes=8;
	for(int b=0;b<nbytes;b++){
		printf("%02hhX",pd->data[b]);
	}
	printf("\n");
}

void process_packet(char *p, endpoint_t *e){
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
	int client_state;
};

typedef struct client_s client_t;

enum {
	C_STATE_R_STATUS,
	C_STATE_RECEIVE,
	C_STATE_QUIT
};

#define BURST_BYTES (256*1024*1024)

void timer_cb(union sigval arg){
	endpoint_t *e = (endpoint_t *)arg.sival_ptr;
	char *data = malloc(BURST_BYTES);
	for(int i=0;i<BURST_BYTES;i++){
		data[i] = i%8;
	}
	char *p1 = packet_data_new(data, BURST_BYTES);
	char *p2 = packet_data_new(data, BURST_BYTES);
	free(data);
	printf("sending burst\n");
	write(e->send_pipe[1], &p1, sizeof(void*));
	write(e->send_pipe[1], &p2, sizeof(void*));
}

void loop_func(endpoint_t *e, void *arg){
	client_t *c = (client_t*)arg;

	timer burst_timer;
	union sigval bt_arg;
	bt_arg.sival_ptr = (void*)e;
	timer_init(&burst_timer, timer_cb, bt_arg);
	timer_set(&burst_timer, 7);

	int loop=1;
	char *p;
	for(;loop;){
		switch(c->client_state){
		case C_STATE_R_STATUS:
		case C_STATE_RECEIVE:
			read(e->recv_pipe[0], &p, sizeof(void*));
			if(!p){
				loop = 0;
			}else{
				process_packet(p, e);
				c->client_state = C_STATE_RECEIVE;
			}
			break;
		case C_STATE_QUIT:
			io_shutdown(e);
			do{
				read(e->recv_pipe[0], &p, sizeof(void*));
				if(p) free(p);
			}while(p);
			loop = 0;
			break;
		}
	}
}

int main( int argc, char *argv[] )
{
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

	client_t c;
	c.client_state = C_STATE_R_STATUS;
	endpoint_process(sfd, loop_func, (void*)&c, 1, 0);

	result = close( sfd );
	if( result == -1 ){
		perror( "close" );
		exit( 1 );
	}
	
	printf( "socket closed\n" );
	
	return 0;
}
	
	
	
	
