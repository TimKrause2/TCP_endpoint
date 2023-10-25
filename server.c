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

#define N_CHILDREN_MAX 4
#define LISTEN_BACKLOG 10

struct shm_data
{
	sem_t sem;
	int N_children;
};

int accept_connection(int sfd){
	int cfd;
	socklen_t peer_addr_size;
	struct sockaddr_storage peer_addr_buf; // big enough for any address
	peer_addr_size = sizeof(peer_addr_buf);
	cfd = accept4(sfd,
				  (struct sockaddr*)&peer_addr_buf,
				  &peer_addr_size,
				  SOCK_NONBLOCK);
	if(cfd==-1){
		perror("accept4");
		return cfd;
	}

	printf("connection accepted\n");

	if(peer_addr_buf.ss_family==AF_INET){
		struct sockaddr_in *peer_addr = (struct sockaddr_in*)&peer_addr_buf;
		printf("\tpeer_addr.sin_port:%hu\n",ntohs( peer_addr->sin_port ) );
		printf("\tpeer_addr.sin_addr:%s\n",inet_ntoa( peer_addr->sin_addr ) );
	}else if(peer_addr_buf.ss_family==AF_INET6){
		struct sockaddr_in6 *peer_addr = (struct sockaddr_in6*)&peer_addr_buf;
		printf("\tpeer_addr.sin6_port:%hu\n",ntohs(peer_addr->sin6_port));
		printf("\tpeer_addr.sin6_addr:");
		for(int i=0;i<16;i++){
			printf("%02X",peer_addr->sin6_addr.s6_addr[i]);
			if(i%4 == 3 && i!=15){
				printf(":");
			}
		}
		printf("\n");
	}else{
		printf("Unknown address family.\n");
	}
	return cfd;
}

bool connection_ok(int sfd){
	char buff[1];
	ssize_t recv_result;
	recv_result = recv(sfd, buff, 1, MSG_DONTWAIT|MSG_PEEK);
	if(recv_result == -1){
		switch(errno){
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
			return true;
		default:
			return false;
		}
	}else if(recv_result==0){
		return false;
	}
	return true;
}

void process_packet_status(struct packet_status *ps){
	switch(ps->header.code){
	case P_ST_CODE_READY:
		break;
	case P_ST_CODE_BUSY:

		break;
	case P_ST_CODE_CONFIRM:
		break;
	}
}

void process_packet_data(struct packet_data *pd){
	int nbytes = pd->header.length - sizeof(struct packet_common);
    printf("data packet: nbytes:%d\n",nbytes);
    if(nbytes>8)nbytes=8;
	for(int b=0;b<nbytes;b++){
		printf("%02hhX",pd->data[b]);
	}
	printf("\n");
}

void process_packet(char *p){
	struct packet_common *header = (struct packet_common *)p;
	switch(header->type){
	case P_STATUS:
		process_packet_status((struct packet_status*)p);
		break;
	case P_DATA:
		process_packet_data((struct packet_data*)p);
		break;
	}
	free(p);
}

enum {
	S_STATE_SEND_STATUS,
	S_STATE_RECEIVE,
	S_STATE_QUIT
};

struct server_s
{
	int server_state;
	int server_status_code;
};

typedef struct server_s server_t;

#define BURST_BYTES (16*1024*1024)

void timer_cb(union sigval arg){
	endpoint_t *e = (endpoint_t *)arg.sival_ptr;
	char *data = malloc(BURST_BYTES);
	for(int i=0;i<BURST_BYTES;i++){
		data[i] = i%8;
	}
	char *p1 = packet_data_new(data, BURST_BYTES);
	free(data);
	printf("sending burst\n");
	write(e->send_pipe[1], &p1, sizeof(void*));
}

void loop_func(endpoint_t *e, void *arg){
	server_t *s = (server_t*)arg;

	timer burst_timer;
	union sigval bt_arg;
	bt_arg.sival_ptr = (void*)e;
	timer_init(&burst_timer, timer_cb, bt_arg);
	timer_set(&burst_timer, 7);

	int loop=1;
	char *p;
	for(;loop;){
		switch(s->server_state){
		case S_STATE_SEND_STATUS:
			p = packet_status_new(s->server_status_code);
			write(e->send_pipe[1], &p, sizeof(void*));
			if(s->server_status_code==P_ST_CODE_BUSY){
				s->server_state = S_STATE_QUIT;
			}else{
				s->server_state = S_STATE_RECEIVE;
			}
			break;
		case S_STATE_RECEIVE:
			read(e->recv_pipe[0], &p, sizeof(void *));
			if(!p){
                printf("loop_func: terminate\n");
				loop=0;
			}else{
                //process_packet(p);
                write(e->send_pipe[1], &p, sizeof(void*));
            }
			break;
		case S_STATE_QUIT:
			io_shutdown(e);
			do{
				read(e->recv_pipe[0], &p, sizeof(void*));
				if(p){
					free(p);
				}
			}while(p);
			loop=0;
			break;
		}
	}
}

int main( int argc, char *argv[] )
{
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
				int cfd = accept_connection(revents[p].data.fd);
				if(cfd<0){
					exit(1);
				}
				printf("cfd:%d\n",cfd);
				server_t s;
				s.server_state = S_STATE_SEND_STATUS;
				if(shm_data->N_children>=N_CHILDREN_MAX){
					printf("max connections reached.\n");
					s.server_status_code = P_ST_CODE_BUSY;
				}else{
					s.server_status_code = P_ST_CODE_READY;
				}
				int pid = fork();
				if(pid<0){
					perror("fork");
					close(cfd);
					continue;
				}else if(pid==0){
					// child process
                    endpoint_process(cfd, loop_func, (void*)&s, 0, 1);
					//printf("child: endpoint_process returned.\n");
					while(sem_wait(&shm_data->sem)==-1){
						perror("sem_wait(child)");
					}
					shm_data->N_children--;
					sem_post(&shm_data->sem);
					exit(0);
				}else{
					printf("child pid:%d\n",pid);
					close(cfd);
					while(sem_wait(&shm_data->sem)==-1){
						perror("sem_wait(parent)");
					}
					shm_data->N_children++;
					sem_post(&shm_data->sem);
				}
			}
		}
	}
}
