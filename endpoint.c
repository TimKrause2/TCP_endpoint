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
#include <openssl/ssl.h>
#include <openssl/err.h>

void socket_set_nonblock(int fd, int nonblock)
{
	int flags = fcntl(fd, F_GETFL);
	if(nonblock){
		flags |= O_NONBLOCK;
	}else{
		flags &= ~O_NONBLOCK;
	}
	fcntl(fd, F_SETFL, flags);
}

void send_timer_cb(union sigval arg)
{
	endpoint_t *e = (endpoint_t*)arg.sival_ptr;

	char *p = packet_status_new(P_ST_CODE_CONFIRM);
	if(!p) return;
	ssize_t r = write(e->send_pipe[1], &p, sizeof(void*));
}

void io_shutdown(endpoint_t *e)
{
	void *data = NULL;
	write(e->term_pipe[1], &data, sizeof(void *));
}

void recv_timer_cb(union sigval arg)
{
	endpoint_t *e = (endpoint_t*)arg.sival_ptr;

	io_shutdown(e);
}

void process_send_ssl(endpoint_t *e)
{
	int r;
	int err;
	for(;;){
		r = SSL_write(e->ssl, e->send_buf, e->send_bytes);
		if(r<=0){
			err = SSL_get_error(e->ssl, r);
			if(err==SSL_ERROR_WANT_WRITE){
				if(e->send_state==SEND_READY){
					epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
					e->send_state = SEND_INPROGRESS;
				}
				return;
			}else{
				printf("process_send_ssl:SSL_write error:%d\n",err);
				e->send_state = SEND_ERROR;
				return;
			}
		}else if(r == e->send_bytes){
			if(e->send_state==SEND_READY){
				epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
			}
			e->send_state = SEND_VERIFY;
			free(e->send_buf_malloc);
			timer_set(&e->send_timer, CONFIRM_TIMEOUT_S);
			return;
		}else{
			e->send_buf += r;
			e->send_bytes -= r;
			timer_set(&e->send_timer, CONFIRM_TIMEOUT_S);
		}
	}
}

void process_send(endpoint_t *e)
{
	ssize_t r;

	while(1){
//		printf("process_send: send(%d, %p, %ld)\n",
//			   e->cfd, e->send_buf, e->send_bytes);
		r = send(e->cfd, e->send_buf, e->send_bytes, 0);
//		printf("r:%ld\n", r);
		if(r==-1){
			switch(errno){
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				if(e->send_state==SEND_READY){
					epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
					e->send_state = SEND_INPROGRESS;
				}
				return;
			default:
				perror("process_send:send");
				e->send_state = SEND_ERROR;
				return;

			}
		}else if(r == e->send_bytes){
			if(e->send_state==SEND_READY){
				epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
			}
			e->send_state = SEND_VERIFY;
			free(e->send_buf_malloc);
			timer_set(&e->send_timer, CONFIRM_TIMEOUT_S);
			return;
		}else{
			e->send_buf += r;
			e->send_bytes -= r;
			timer_set(&e->send_timer, CONFIRM_TIMEOUT_S);
		}
	}
}

void process_recv_ssl(endpoint_t *e)
{
	int r;
	int err;
	struct packet_common header;
	for(;;){
		switch(e->recv_state){
		case RECV_HEADER:
			r = SSL_peek(e->ssl, &header, sizeof(header));
			if(r<=0){
				err = SSL_get_error(e->ssl, r);
				if(err==SSL_ERROR_WANT_READ){
					return;
				}else{
					printf("process_recv_ssl:SSL_peek error:%d\n", err);
					e->recv_state = RECV_ERROR;
					return;
				}
			}else if(r == sizeof(header)){
				e->recv_buf_malloc = e->recv_buf = malloc(header.length);
				if(!e->recv_buf){
					perror("process_recv_ssl:malloc");
					e->recv_state = RECV_ERROR;
					return;
				}
				e->recv_bytes = header.length;
				e->recv_state = RECV_INPROGRESS;
			}
			break;
		case RECV_INPROGRESS:
			r = SSL_read(e->ssl, e->recv_buf, e->recv_bytes);
			if(r<=0){
				err = SSL_get_error(e->ssl, r);
				if(err==SSL_ERROR_WANT_READ){
					return;
				}else{
					printf("proces_recv_ssl:SSL_read error:%d\n",err);
					free(e->recv_buf_malloc);
					e->recv_state = RECV_ERROR;
					return;
				}
			}else if(r == e->recv_bytes){
				write(e->recv_pipe[1], &e->recv_buf_malloc, sizeof(void*));
				timer_set(&e->recv_timer, WATCHDOG_TIMEOUT_S);
				e->recv_state = RECV_HEADER;
				return;
			}else{
				e->recv_buf += r;
				e->recv_bytes -= r;
				timer_set(&e->recv_timer, WATCHDOG_TIMEOUT_S);
			}
			break;
		case RECV_ERROR:
			return;
		}
	}
}

void process_recv(endpoint_t *e)
{
	ssize_t r;
	while(1){
		if(e->recv_state==RECV_HEADER){
			struct packet_common header;
			r = recv(e->cfd, &header, sizeof(header), MSG_PEEK);
			if(r==-1){
				perror("process_recv:recv(MSG_PEEK)");
				e->recv_state = RECV_ERROR;
				return;
			}
			if (r==0){
				printf("process_recv:connection lost\n");
				e->recv_state = RECV_ERROR;
				return;
			}
			e->recv_buf_malloc = e->recv_buf = malloc(header.length);
			if(!e->recv_buf){
				perror("process_recv:malloc");
				e->recv_state = RECV_ERROR;
				return;
			}
			e->recv_bytes = header.length;
			e->recv_state = RECV_INPROGRESS;
		}else if(e->recv_state==RECV_INPROGRESS){
			r = recv(e->cfd, e->recv_buf, e->recv_bytes, 0);
			if(r==-1){
				switch(errno){
				case EAGAIN:
#if EAGAIN != EWOULDBLOCK
				case EWOULDBLOCK:
#endif
					return;
				default:
					perror("process_recv:recv");
					e->recv_state = RECV_ERROR;
					free(e->recv_buf_malloc);
					return;
				}
			}else if(r == e->recv_bytes){
				e->recv_state = RECV_HEADER;
				write(e->recv_pipe[1], &e->recv_buf_malloc, sizeof(void*));
				timer_set(&e->recv_timer, WATCHDOG_TIMEOUT_S);
				return;
			}else if(r == 0){
				free(e->recv_buf_malloc);
				e->recv_state = RECV_ERROR;
				return;
			}else{
				e->recv_buf += r;
				e->recv_bytes -= r;
				timer_set(&e->recv_timer, WATCHDOG_TIMEOUT_S);
			}
		}else if(e->recv_state==RECV_ERROR){
			return;
		}
	}
}

void recv_terminate(endpoint_t *e)
{
	void *data = NULL;
	write(e->recv_pipe[1], &data, sizeof(void*));
}

void *io_routine(void *arg){
	endpoint_t *e = (endpoint_t*)arg;
	int result;

	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigfillset(&sa.sa_mask);
	sa.sa_restorer = NULL;

	result = sigaction(SIGUSR1, &sa, NULL);
	if(result==-1){
		perror("sigaction");
		recv_terminate(e);
		return NULL;
	}

	e->epfd = epoll_create1(0);
	if(e->epfd==-1){
		perror("io_routine:epoll_create1(0)");
		recv_terminate(e);
		return NULL;
	}
	struct epoll_event revents[3];

	result = epoll_ctl(e->epfd, EPOLL_CTL_ADD, e->cfd, &e->ev_cfd_r);
	if(result==-1){
		perror("io_routtine:epoll_ctl(ADD cfd)");
		recv_terminate(e);
		return NULL;
	}

	result = epoll_ctl(e->epfd, EPOLL_CTL_ADD, e->send_pipe[0], &e->ev_send);
	if(result==-1){
		perror("io_routtine:epoll_ctl(ADD send_pipe[0])");
		recv_terminate(e);
		return NULL;
	}

	result = epoll_ctl(e->epfd, EPOLL_CTL_ADD, e->term_pipe[0], &e->ev_term);
	if(result==-1){
		perror("io_routine:epoll_ctl(ADD term_pipe[0])");
		recv_terminate(e);
		return NULL;
	}

	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);

	for(;;){
		int r = epoll_pwait(e->epfd, revents, 3, -1, &sigmask);
		if(r==-1){
			perror("io_routine:epoll_wait");
			continue;
		}
//		printf("r:%d\n",r);
		for(int i=0;i<r;i++){
//			printf("i:%d revents[i].data.fd:%d revents[i].events:%x\n",
//				   i, revents[i].data.fd, revents[i].events);
			if(revents[i].data.fd==e->send_pipe[0]){
//				printf("send_pipe[0] revents:%x.\n", revents[i].events);
				if(revents[i].events&EPOLLIN){
					ssize_t r = read(e->send_pipe[0], &e->send_buf_malloc, sizeof(void*));
					if(r==-1){
						perror("io_routine:read(send_pipe[0])");
						continue;
					}
					e->send_buf = e->send_buf_malloc;
					struct packet_common *header = (struct packet_common*)e->send_buf_malloc;
					e->send_bytes = header->length;
					e->process_send_cb(e);
				}
			}else if(revents[i].data.fd == e->cfd){
//				printf("cfd revents:%x\n",revents[i].events);
				if(revents[i].events&EPOLLIN){
					e->process_recv_cb(e);
				}
				if(revents[i].events&EPOLLOUT){
					if(e->send_state==SEND_VERIFY){
						epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_r);
						e->send_state=SEND_READY;
						result = epoll_ctl(e->epfd, EPOLL_CTL_MOD,
										   e->send_pipe[0], &e->ev_send);
						if(result==-1){
							perror("io_routtine:epoll_ctl(MOD send_pipe[0])");
							recv_terminate(e);
							return NULL;
						}
					}else{
						e->process_send_cb(e);
					}
				}
			}else if(revents[i].data.fd==e->term_pipe[0]){
				if(revents[i].events&EPOLLIN){
					void *p;
					read(e->term_pipe[0], &p, sizeof(void*));
					recv_terminate(e);
					return NULL;
				}
			}
		}
		if(e->send_state==SEND_ERROR || e->recv_state==RECV_ERROR){
			printf("io_routine: ERROR quit.\n");
			recv_terminate(e);
			return NULL;
		}
	}
}

void SSL_print_error(char *context)
{
	printf("%s:%s\n", context,
		   ERR_error_string(ERR_get_error(),NULL));
}

void SSL_perror(char *message, SSL *ssl, int result ){
	int error = SSL_get_error(ssl, result);
	char *error_str;
	switch(error){
	case SSL_ERROR_NONE:
		error_str = "SSL_ERROR_NONE";
		break;

	case SSL_ERROR_ZERO_RETURN:
		error_str = "SSL_ERROR_ZERO_RETURN";
		break;

	case SSL_ERROR_WANT_READ:
		error_str = "SSL_ERROR_WANT_READ";
		break;

	case SSL_ERROR_WANT_WRITE:
		error_str = "SSL_ERROR_WANT_WRITE";
		break;

	case SSL_ERROR_WANT_CONNECT:
		error_str = "SSL_ERROR_WANT_CONNECT";
		break;

	case SSL_ERROR_WANT_ACCEPT:
		error_str = "SSL_ERROR_WANT_ACCEPT";
		break;

	case SSL_ERROR_WANT_X509_LOOKUP:
		error_str = "SSL_ERROR_WANT_X509_LOOKUP";
		break;

	case SSL_ERROR_WANT_ASYNC:
		error_str = "SSL_ERROR_WANT_ASYNC";
		break;

	case SSL_ERROR_WANT_ASYNC_JOB:
		error_str = "SSL_ERROR_WANT_ASYNC_JOB";
		break;

	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		error_str = "SSL_ERROR_WANT_CLIENT_HELLO_CB";
		break;

	case SSL_ERROR_SYSCALL:
		error_str = "SSL_ERROR_SYSCALL";
		break;

	case SSL_ERROR_SSL:
		error_str = "SSL_ERROR_SSL";
		break;

	default:
		error_str = "Unknown Error";
		break;
	}

	printf("Error in %s:%s\n",message,error_str);

	if(error == SSL_ERROR_SYSCALL){
		perror(message);
	}else if(error == SSL_ERROR_SSL){
		printf("%s\n", ERR_error_string(ERR_get_error(),NULL));
	}
}

void endpoint_process(
		int cfd,
		loop_func_ptr loop_func,
		void *loop_func_arg,
		int ssl_enable,
		int server)
{
	endpoint_t *e;
	e = malloc(sizeof(endpoint_t));
	if(!e)return;
	e->cfd = cfd;
	e->send_state = SEND_READY;
	e->recv_state = RECV_HEADER;

	memset(&e->ev_cfd_r, 0, sizeof(struct epoll_event));
	memset(&e->ev_cfd_rw, 0, sizeof(struct epoll_event));
	memset(&e->ev_send, 0, sizeof(struct epoll_event));
	memset(&e->ev_term, 0, sizeof(struct epoll_event));

	if(ssl_enable){
		e->ssl_enable = 1;
		e->process_recv_cb = process_recv_ssl;
		e->process_send_cb = process_send_ssl;
		if(server){
			e->server = 1;
			e->ssl_ctx = SSL_CTX_new(TLS_server_method());
			if(!e->ssl_ctx){
				SSL_print_error("SSL_CTX_new");
				return;
			}

			int result = SSL_CTX_use_certificate_chain_file(
						e->ssl_ctx,
						"fullchain.pem");
			if(result!=1){
				SSL_print_error("SSL_CTX_use_certificate_chain_file");
				return;
			}

			result = SSL_CTX_use_PrivateKey_file(
						e->ssl_ctx,
						"privkey.pem",
						SSL_FILETYPE_PEM);
			if(result!=1){
				SSL_print_error("SSL_CTX_use_PrivateKey_file");
				return;
			}

			e->ssl = SSL_new(e->ssl_ctx);
			if(!e->ssl){
				SSL_print_error("SSL_new");
				return;
			}

			result = SSL_set_fd(e->ssl, e->cfd);
			if(result=0){
				SSL_print_error("SSL_set_fd");
				return;
			}

			socket_set_nonblock(e->cfd, 0);

			result = SSL_accept(e->ssl);
			if(result<=0){
				SSL_perror("SSL_accept", e->ssl, result );
				return;
			}

			socket_set_nonblock(e->cfd, 1);
		}else{
			e->server = 0;
			e->ssl_ctx = SSL_CTX_new(TLS_client_method());
			if(!e->ssl_ctx){
				SSL_print_error("SSL_CTX_new");
				return;
			}

			e->ssl = SSL_new(e->ssl_ctx);
			if(!e->ssl){
				SSL_print_error("SSL_new");
				return;
			}

			int result = SSL_set_fd(e->ssl, e->cfd);
			if(result==0){
				SSL_print_error("SSL_set_fd");
				return;
			}

			socket_set_nonblock(e->cfd, 0);

			result = SSL_connect(e->ssl);
			if(result<=0){
				SSL_perror("SSL_connect",e->ssl,result);
				return;
			}

			socket_set_nonblock(e->cfd, 1);
		}
	}else{
		e->ssl_enable = 0;
		e->process_recv_cb = process_recv;
		e->process_send_cb = process_send;
	}

	int r;
	r = pipe(e->send_pipe);
	if(r<0){
		perror("process_connection:pipe(send_pipe)");
		return;
	}

	r = pipe(e->recv_pipe);
	if(r<0){
		perror("process_connection:pipe(recv_pipe)");
		return;
	}

	r = pipe(e->term_pipe);
	if(r<0){
		perror("process_connection:pipe(term_pipe)");
		return;
	}

	union sigval arg;
	arg.sival_ptr = (void*)e;

	r = timer_init(&e->send_timer, send_timer_cb, arg);
	if(r==-1){
		perror("timer_init(send_timer)");
		return;
	}

	r = timer_init(&e->recv_timer, recv_timer_cb, arg);
	if(r==-1){
		perror("timer_init(recv_timer)");
		return;
	}

	timer_set(&e->send_timer, CONFIRM_TIMEOUT_S);
	timer_set(&e->recv_timer, WATCHDOG_TIMEOUT_S);

	e->ev_cfd_r.data.fd = e->cfd;
	e->ev_cfd_rw.data.fd = e->cfd;
	e->ev_cfd_r.events = EPOLLIN;
	e->ev_cfd_rw.events = EPOLLIN | EPOLLOUT;
	e->ev_send.data.fd = e->send_pipe[0];
	e->ev_send.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	e->ev_term.data.fd = e->term_pipe[0];
	e->ev_term.events = EPOLLIN;

	r = pthread_create(&e->io_thread, NULL, io_routine, (void*)e);
	if(r!=0){
		errno = r;
		perror("pthread_create");
		return;
	}

	loop_func(e, loop_func_arg);

	pthread_join(e->io_thread, NULL);

}

