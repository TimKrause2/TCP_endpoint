#include "endpoint.h"
#define __USE_GNU
#include <sys/types.h>
#define _GNU_SOURCE
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

void ignore_sigpipe(void)
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_restorer = NULL;

    int result = sigaction(SIGPIPE, &sa, NULL);
    if(result==-1)
    {
        perror("ignore_sigpipe: sigaction(SIGPIPE,...)");
        exit(1);
    }
}

void send_timer_cb(void * arg)
{
    endpoint_t *e = (endpoint_t*)arg;

	char *p = packet_status_new(P_ST_CODE_CONFIRM);
	if(!p) return;
	ssize_t r = write(e->send_pipe[1], &p, sizeof(void*));
}

void io_shutdown(endpoint_t *e)
{
	void *data = NULL;
	write(e->term_pipe[1], &data, sizeof(void *));
}

void recv_timer_cb(void * arg)
{
    endpoint_t *e = (endpoint_t*)arg;

	io_shutdown(e);
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

void process_send_ssl(void *arg)
{
    endpoint_t *e = (endpoint_t*)arg;
    if(e->send_state==SEND_VERIFY){
        e->send_state=SEND_READY;
        int result = epoll_ctl(e->epfd, EPOLL_CTL_MOD,
                           e->cfd, &e->ev_cfd_r);
        if(result==-1){
            perror("process_send_ssl:epoll_ctl(MOD cfd)");
            e->send_state = SEND_ERROR;
            return;
        }

        result = epoll_ctl(e->epfd, EPOLL_CTL_MOD,
                           e->send_pipe[0], &e->ev_send);
        if(result==-1){
            perror("process_send_ssl:epoll_ctl(MOD send_pipe[0])");
            e->send_state = SEND_ERROR;
            return;
        }
        return;
    }
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
                free(e->send_buf_malloc);
				return;
			}
		}else if(r == e->send_bytes){
			if(e->send_state==SEND_READY){
				epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
			}
			e->send_state = SEND_VERIFY;
			free(e->send_buf_malloc);
            timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
			return;
		}else{
			e->send_buf += r;
			e->send_bytes -= r;
            timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
		}
	}
}

void process_send(void *arg)
{
    endpoint_t *e = (endpoint_t*)arg;
    ssize_t r;
    if(e->send_state==SEND_VERIFY){
        e->send_state=SEND_READY;
        int result = epoll_ctl(e->epfd, EPOLL_CTL_MOD,
                           e->cfd, &e->ev_cfd_r);
        if(result==-1){
            perror("process_send:epoll_ctl(MOD cfd)");
            e->send_state = SEND_ERROR;
            return;
        }

        result = epoll_ctl(e->epfd, EPOLL_CTL_MOD,
                           e->send_pipe[0], &e->ev_send);
        if(result==-1){
            perror("process_send:epoll_ctl(MOD send_pipe[0])");
            e->send_state = SEND_ERROR;
            return;
        }
        return;
    }
	while(1){
//		printf("process_send: send(%d, %p, %ld)\n",
//			   e->cfd, e->send_buf, e->send_bytes);
		r = send(e->cfd, e->send_buf, e->send_bytes, 0);
//		printf("r:%ld\n", r);
		if(r==-1){
            if(errno==EAGAIN || errno==EWOULDBLOCK)
            {
				if(e->send_state==SEND_READY){
					epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
					e->send_state = SEND_INPROGRESS;
				}
				return;
            } else {
				perror("process_send:send");
                printf("errno:%d\n",errno);
                free(e->send_buf_malloc);
				e->send_state = SEND_ERROR;
				return;
			}
		}else if(r == e->send_bytes){
			if(e->send_state==SEND_READY){
				epoll_ctl(e->epfd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_rw);
			}
			e->send_state = SEND_VERIFY;
			free(e->send_buf_malloc);
            timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
			return;
		}else{
			e->send_buf += r;
			e->send_bytes -= r;
            timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
		}
	}
}

void process_recv_ssl(void *arg)
{
    endpoint_t *e = (endpoint_t*)arg;
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
					SSL_perror("process_recv_ssl:SSL_peek error",
									e->ssl, r);
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
                timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);
				e->recv_state = RECV_HEADER;
				return;
			}else{
				e->recv_buf += r;
				e->recv_bytes -= r;
                timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);
			}
			break;
		case RECV_ERROR:
			return;
		}
	}
}

void process_recv(void *arg)
{
    endpoint_t *e = (endpoint_t*)arg;
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
                    printf("errno:%d\n",errno);
                    e->recv_state = RECV_ERROR;
					free(e->recv_buf_malloc);
					return;
				}
			}else if(r == e->recv_bytes){
				e->recv_state = RECV_HEADER;
				write(e->recv_pipe[1], &e->recv_buf_malloc, sizeof(void*));
                timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);
				return;
			}else if(r == 0){
				free(e->recv_buf_malloc);
				e->recv_state = RECV_ERROR;
				return;
			}else{
				e->recv_buf += r;
				e->recv_bytes -= r;
                timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);
			}
		}else if(e->recv_state==RECV_ERROR){
			return;
		}
	}
}

void process_send_pipe(void *arg)
{
    endpoint_t *e = (endpoint_t*)arg;
    ssize_t r = read(e->send_pipe[0], &e->send_buf_malloc, sizeof(void*));
    if(r==-1){
        perror("process_send_pipe:read(send_pipe[0])");
        return;
    }
    e->send_buf = e->send_buf_malloc;
    struct packet_common *header = (struct packet_common*)e->send_buf_malloc;
    e->send_bytes = header->length;
    e->process_send_cb(e);
}

void process_term(void *arg)
{
    endpoint_t *e = (endpoint_t*)arg;
    void *p;
    read(e->term_pipe[0], &p, sizeof(void*));
    e->io_terminate = 1;
}


void recv_terminate(endpoint_t *e)
{
	void *data = NULL;
	write(e->recv_pipe[1], &data, sizeof(void*));
}

void *io_routine(void *arg){
	endpoint_t *e = (endpoint_t*)arg;
	int result;

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

	for(;;){
		int r = epoll_wait(e->epfd, revents, 3, -1);
		if(r==-1){
			perror("io_routine:epoll_wait");
			continue;
		}
        for(int i=0;i<r;i++)
        {
            struct epoll_dispatch *ed =
                    (struct epoll_dispatch*)revents[i].data.ptr;

            if(ed->in_cb && revents[i].events&EPOLLIN)
            {
                ed->in_cb(ed->arg);
            }

            if(ed->out_cb && revents[i].events&EPOLLOUT)
            {
                ed->out_cb(ed->arg);
            }
        }

        if((e->send_state==SEND_ERROR)
                || (e->recv_state==RECV_ERROR)
                || e->io_terminate)
        {
            printf("io_routine: ERROR or io_terminate.\n");
            if(e->recv_state == RECV_INPROGRESS)
            {
                free(e->recv_buf_malloc);
            }
            if(e->send_state == SEND_INPROGRESS)
            {
                free(e->send_buf_malloc);
            }
            ssize_t r;
            void *packet;
            socket_set_nonblock(e->send_pipe[0], 1);
            while((r=read(e->send_pipe[0], &packet, sizeof(void*)))==sizeof(void*))
            {
                if(packet)
                    free(packet);
            }
            recv_terminate(e);
            return NULL;
		}
	}
}

void endpoint_process(
		int cfd,
		loop_func_ptr loop_func,
		void *loop_func_arg,
		int ssl_enable,
		int server)
{
    ignore_sigpipe();
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

    e->send_timer = timer_new(send_timer_cb, e);
    if(!e->send_timer){
        printf("Problem obtaining send_timer.\n");
        return;
    }

    e->recv_timer = timer_new(recv_timer_cb, e);
    if(!e->recv_timer){
        printf("Problem obtaining recv_timer.\n");
        return;
    }
    timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
    timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);

    e->ev_cfd_r.data.ptr = &e->ed_cfd;
    e->ev_cfd_rw.data.ptr = &e->ed_cfd;
	e->ev_cfd_r.events = EPOLLIN;
	e->ev_cfd_rw.events = EPOLLIN | EPOLLOUT;
    e->ev_send.data.ptr = &e->ed_send;
	e->ev_send.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    e->ev_term.data.ptr = &e->ed_term;
	e->ev_term.events = EPOLLIN;

    e->ed_cfd.arg = e;
    e->ed_cfd.in_cb = e->process_recv_cb;
    e->ed_cfd.out_cb = e->process_send_cb;
    e->ed_send.arg = e;
    e->ed_send.in_cb = process_send_pipe;
    e->ed_send.out_cb = NULL;
    e->ed_term.arg = e;
    e->ed_term.in_cb = process_term;
    e->ed_term.out_cb = NULL;

    e->io_terminate = 0;

    r = pthread_create(&e->io_thread, NULL, io_routine, (void*)e);
	if(r!=0){
		errno = r;
		perror("pthread_create");
		return;
	}

	loop_func(e, loop_func_arg);

	pthread_join(e->io_thread, NULL);

}

/***********************************************************************
 *
 * No fork, epoll version
 */
sem_t el_sem; // endpoint list semaphore
ele *el_head = NULL;
int N_endpoints = 0;
int send_epoll_fd;
int recv_epoll_fd;
int N_send_threads;
int N_recv_threads;
tds *send_tds;
tds *recv_tds;
timer *per_second_timer;

void endpoint_check(endpoint *e);

int  endpoint_list_init(void)
{
    int r = sem_init(&el_sem, 0, 1);
    if(r==-1){
        perror("endpoint_list_init: sem_init");
        return 0;
    }
    el_head = NULL;
    return 1;
}

void endpoint_list_lock(void)
{
    int r = sem_wait(&el_sem);
    if(r==-1){
        perror("endpoint_list_lock: sem_wait");
    }
}

void endpoint_list_unlock(void)
{
    int r = sem_post(&el_sem);
    if(r==-1){
        perror("endpoint_list_unlock: sem_post");
    }
}

ele *endpoint_list_push(endpoint *e)
{
    ele *le = malloc(sizeof(ele));
    if(!le){
        perror("endpoint_list_push: malloc");
        endpoint_close(e);
        return NULL;
    }
    le->e = e;
    endpoint_list_lock();
    if(!el_head){
        el_head = le;
        le->next = NULL;
        le->prev = NULL;
    }else{
        el_head->prev = le;
        le->next = el_head;
        le->prev = NULL;
        el_head = le;
    }
    N_endpoints++;
    endpoint_list_unlock();
    return le;
}

void endpoint_list_remove_raw(ele *le)
{
    if(el_head == le){
        if(el_head->next){
            el_head->next->prev = NULL;
        }
        el_head = el_head->next;
    }else{
        le->prev->next = le->next;
        if(le->next)
            le->next->prev = le->prev;
    }
    free(le);
    N_endpoints--;
}

void endpoint_list_remove(ele *le)
{
    endpoint_list_lock();
    endpoint_list_remove_raw(le);
    endpoint_list_unlock();
}

cals *cal_new(void)
{
    cals *s = malloc(sizeof(cals));
    if(!s){
        perror("cal_new: malloc");
        return NULL;
    }
    s->head = NULL;
    s->tail = NULL;
    return s;
}

void cal_delete(cals *s)
{
    free(s);
}

void cal_push(cals *s, void *packet, endpoint *e)
{
    cale *le = malloc(sizeof(cale));
    if(!le){
        perror("cal_push: malloc");
        free(packet);
        return;
    }
    le->e = e;
    le->packet = packet;
    if(s->head == NULL){
        s->head = le;
        s->tail = le;
        le->next = NULL;
    }else{
        s->tail->next = le;
        s->tail = le;
        le->next = NULL;
    }
}

void cal_call(cals *s)
{
    cale *le = s->head;
    while(le){
        endpoint_send(le->e, le->packet);
        cale *lef = le;
        le = le->next;
        free(lef);
    }
    s->head = NULL;
    s->tail = NULL;
}

void *send_thread_routine(void *arg)
{
    tds *s = (tds*)arg;
    printf("send_thread_routine: thread num=%d\n", s->num);

    for(;;){
        struct epoll_event event;
        int Nevents = epoll_wait(send_epoll_fd, &event, 1, -1);
        if(Nevents==-1){
            perror("send_thread_routine:epoll_wait");
            continue;
        }else if(Nevents){
            epoll_dispatch *ed = (epoll_dispatch*)event.data.ptr;
            //printf("send_thread_routine: calling thread num=%d arg=0x%p\n", s->num, ed->arg);
            ed->out_cb(ed->arg);
        }
    }
}

void *recv_thread_routine(void *arg)
{
    tds *s = (tds*)arg;
    printf("recv_thread_routine: thread num=%d\n", s->num);

    for(;;){
        struct epoll_event event;
        int Nevents = epoll_wait(recv_epoll_fd, &event, 1, -1);
        if(Nevents==-1){
            perror("recv_thread_routine:epoll_wait");
            continue;
        }else if(Nevents){
            epoll_dispatch *ed = (epoll_dispatch*)event.data.ptr;
            //printf("recv_thread_routine: calling... thread num=%d, arg=%p\n",s->num,ed->arg);
            ed->in_cb(ed->arg);
        }
    }
}

char *send_state_str(int send_state)
{
    switch(send_state)
    {
    case SEND_OPEN:
        return "SEND_OPEN";
    case SEND_READY:
        return "SEND_READY";
    case SEND_INPROGRESS:
        return "SEND_INPROGRESS";
    case SEND_VERIFY:
        return "SEND_VERIFY";
    case SEND_ERROR:
        return "SEND_ERROR";
    default:
        return "Unknown";
    }
}

void process_send2(void *arg)
{
    //printf("process_send2: arg=%p\n",arg);
    endpoint *e = (endpoint*)arg;
    ssize_t r;
    if(e->send_locked_out) return;
    sem_wait(&e->send_sem);
    if(e->send_locked_out)
        goto return_unlock;
    if(e->send_state==SEND_OPEN){
        // Unexpected event - must be an error
        printf("process_send2: send_state==SEND_OPEN\n");
        goto error_unlock;
    }
    if(e->send_state==SEND_ERROR){
        goto return_unlock;
    }
    if(e->send_state==SEND_VERIFY){
        //printf("process_send2: deleting e->cfd from interest list.\n");
        int result = epoll_ctl(send_epoll_fd, EPOLL_CTL_DEL,
                           e->cfd, NULL);
        if(result==-1){
            perror("process_send2:epoll_ctl(DEL cfd)");
            //goto error_unlock;
        }
        s_ptr *sp = fifo_read(e->send_fifo);
        if(sp){
            e->send_buf_s_ptr = sp;
            e->send_buf = shared_ptr_data(sp);
            e->send_bytes = packet_length(e->send_buf);
            e->send_state = SEND_READY;
            goto procede_to_send;
        }else{
            e->send_state=SEND_OPEN;
        }
        goto return_unlock;
    }
procede_to_send:
    while(1){
//		printf("process_send: send(%d, %p, %ld)\n",
//			   e->cfd, e->send_buf, e->send_bytes);
        r = send(e->cfd, e->send_buf, e->send_bytes, 0);
//		printf("r:%ld\n", r);
        if(r==-1){
            if(errno==EAGAIN || errno==EWOULDBLOCK)
            {
                if(e->send_state==SEND_READY){
                    //printf("process_send2: inprogress ADD e->cfd\n");
                    int result = epoll_ctl(send_epoll_fd, EPOLL_CTL_ADD, e->cfd, &e->ev_cfd_w);
                    if(result==-1){
                        perror("process_send2: epoll_ctl EAGAIN");
                        //goto error_unlock;
                    }
                    e->send_state = SEND_INPROGRESS;
                }
                goto return_unlock;
            } else {
                perror("process_send2: send");
                printf("errno:%d\n",errno);
                shared_ptr_free(e->send_buf_s_ptr);
                goto error_unlock;
            }
        }else if(r == e->send_bytes){
            //printf("process_send2: send complete r=%ld\n", e->send_bytes);
            shared_ptr_free(e->send_buf_s_ptr);
            timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
            if(e->send_state==SEND_READY){
                //printf("process_send2: complete ADD e->cfd\n");
                int result = epoll_ctl(send_epoll_fd, EPOLL_CTL_ADD, e->cfd, &e->ev_cfd_w);
                if(result==-1){
                    perror("process_send2: epoll_ctl verify");
                    //goto error_unlock;
                }
            }
            if(e->send_state==SEND_INPROGRESS){
                //printf("process_send2: complete MOD e->cfd\n");
                int result = epoll_ctl(send_epoll_fd, EPOLL_CTL_MOD, e->cfd, &e->ev_cfd_w);
                if(result==-1){
                    perror("process_send2: epoll_ctl verify");
                    //goto error_unlock;
                }
            }
            e->send_state = SEND_VERIFY;
            goto return_unlock;
        }else{
            e->send_buf += r;
            e->send_bytes -= r;
            timer_set(e->send_timer, CONFIRM_TIMEOUT_S);
        }
    }

error_unlock:
    e->send_state = SEND_ERROR;
    e->send_locked_out = 1;
    epoll_ctl(send_epoll_fd, EPOLL_CTL_DEL, e->cfd, NULL);

return_unlock:
    //printf("process_send2: e->send_state:%s\n", send_state_str(e->send_state));
    sem_post(&e->send_sem);
}

void process_recv2(void *arg)
{
    endpoint *e = (endpoint*)arg;
    void *packet = NULL;
    if(e->recv_locked_out) return;
    sem_wait(&e->recv_sem);
    if(e->recv_locked_out)
        goto normal_return;

    if(e->recv_state == RECV_ERROR)
        goto normal_return;

    ssize_t r;
    while(1) {
        if(e->recv_state==RECV_HEADER){
            struct packet_common header;
            r = recv(e->cfd, &header, sizeof(header), MSG_PEEK);
            if(r==-1){
                if(errno==EAGAIN || errno==EWOULDBLOCK){
                    goto normal_return;
                }
                perror("process_recv:recv(MSG_PEEK)");
                printf("errno:%d\n",errno);
                goto error_return;
            }
            if (r==0){
                printf("process_recv:connection lost\n");
                goto error_return;
            }
            e->recv_buf_malloc = e->recv_buf = malloc(header.length);
            if(!e->recv_buf){
                perror("process_recv:malloc");
                goto error_return;
            }
            e->recv_bytes = header.length;
            e->recv_state = RECV_INPROGRESS;
        }else if(e->recv_state==RECV_INPROGRESS){
            r = recv(e->cfd, e->recv_buf, e->recv_bytes, 0);
            if(r==-1){
                if(errno==EAGAIN || errno==EWOULDBLOCK){
                    goto normal_return;
                }else{
                    perror("process_recv:recv");
                    printf("errno:%d\n",errno);
                    free(e->recv_buf_malloc);
                    goto error_return;
                }
            }else if(r == e->recv_bytes){
                e->recv_state = RECV_HEADER;
                timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);
                packet = e->recv_buf_malloc;
                goto normal_return;
            }else if(r == 0){
                free(e->recv_buf_malloc);
                goto error_return;
            }else{
                e->recv_buf += r;
                e->recv_bytes -= r;
                timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);
            }
        }else if(e->recv_state==RECV_ERROR){
            goto normal_return;
        }
    }

error_return:
    e->recv_state = RECV_ERROR;
    e->recv_locked_out = 1;
    epoll_ctl(recv_epoll_fd, EPOLL_CTL_DEL, e->cfd, NULL);
    sem_post(&e->recv_sem);
    return;

normal_return:
    if(packet)
        e->recv_packet_cb(packet, e);
    sem_post(&e->recv_sem);
    return;

}

void endpoint_reap(endpoint *e);

void per_second_cb(void *)
{
    endpoint_list_lock();
    ele *le = el_head;
    while(le) {
        endpoint *e = le->e;
        int free_le = 0;
        if(e->locked_out || e->send_locked_out || e->recv_locked_out){
            free_le = 1;
            endpoint_reap(e);
        }
        ele *lef = le;
        le = le->next;
        if(free_le){
            endpoint_list_remove_raw(lef);
            free(e);
        }
    }
    endpoint_list_unlock();
}

void send_expire_cb(void *arg)
{
    endpoint *e = arg;
    char *p = packet_status_new(P_ST_CODE_CONFIRM);
    if(!p) return;
    s_ptr *sp = shared_ptr_new(p);
    if(!sp){
        free(p);
    }else{
        endpoint_send(e, sp);
    }
}

void recv_expire_cb(void *arg)
{
    endpoint *e = arg;

    endpoint_close(e);
}

int endpoints_init(int N_send_threads_in, int N_recv_threads_in)
{
    // initilialize the endpoint list semaphore
    if(!endpoint_list_init()){
        printf("endpoints_init: Couldn't initialize endpoint list.\n");
        return 0;
    }

    // create the read and send epoll instances
    send_epoll_fd = epoll_create1(0);
    if(send_epoll_fd==-1){
        perror("endpoints_init: epoll_create1 send");
        return 0;
    }

    recv_epoll_fd = epoll_create1(0);
    if(recv_epoll_fd==-1){
        perror("endpoints_init: epoll_create1 recv");
        return 0;
    }

    // create the thread data structures
    N_send_threads = N_send_threads_in;
    N_recv_threads = N_recv_threads_in;
    send_tds = malloc(N_send_threads*sizeof(tds));
    if(!send_tds){
        perror("endpoints_init: malloc send tds");
        return 0;
    }
    int i;
    for(i=0;i<N_send_threads;i++){
        send_tds[i].num = i+1;
        int r = pthread_create(&send_tds[i].thread, NULL, send_thread_routine, &send_tds[i]);
        if(r!=0){
            printf("endpoints_init: pthread_create: send error=%d\n",r);
            return 0;
        }
    }

    recv_tds = malloc(N_recv_threads*sizeof(tds));
    if(!recv_tds){
        perror("endpoints_init: malloc send tds");
        return 0;
    }
    for(i=0;i<N_recv_threads;i++){
        recv_tds[i].num = i+1;
        int r = pthread_create(&recv_tds[i].thread, NULL, recv_thread_routine, &recv_tds[i]);
        if(r!=0){
            printf("endpoints_init: pthread_create: recv error=%d\n",r);
            return 0;
        }
    }

    per_second_timer = timer_new(per_second_cb, NULL);
    if(!per_second_timer){
        printf("endpoints_init: timer_new\n");
        return 0;
    }

    timer_set(per_second_timer, -1);

    ignore_sigpipe();

    return 1;
}

int endpoint_accept(endpoint *e, int sfd){
    int cfd;
    socklen_t peer_addr_size;
    peer_addr_size = sizeof(e->peer_addr);
    cfd = accept4(sfd,
                  (struct sockaddr*)&e->peer_addr,
                  &peer_addr_size,
                  SOCK_NONBLOCK);
    if(cfd==-1){
        perror("endpoint_accept: accept4");
        return cfd;
    }

    printf("endpoint_accept: connection accepted cfd=%d\n",cfd);

    if(e->peer_addr.ss_family==AF_INET){
        struct sockaddr_in *peer_addr = (struct sockaddr_in*)&e->peer_addr;
        printf("\tpeer_addr.sin_port:%hu\n",ntohs( peer_addr->sin_port ) );
        printf("\tpeer_addr.sin_addr:%s\n",inet_ntoa( peer_addr->sin_addr ) );
    }else if(e->peer_addr.ss_family==AF_INET6){
        struct sockaddr_in6 *peer_addr = (struct sockaddr_in6*)&e->peer_addr;
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

endpoint* endpoint_new(int fd,
        void (*recv_packet_cb)(void *, endpoint *e),
        void *recv_cb_arg,
        int ssl_enable,
        int is_server)
{
    int result;
    // allocate a new endpoint object
    endpoint *e = malloc(sizeof(endpoint));
    if(!e) {
        perror("endpoint_new: malloc endpoint");
        return NULL;
    }

    // initialize the object
    e->send_timer = timer_new(send_expire_cb, e);
    if(!e->send_timer){
        printf("endpoint_new: send_timer failed\n");
        goto error_free;
    }
    timer_set(e->send_timer, CONFIRM_TIMEOUT_S);

    e->recv_timer = timer_new(recv_expire_cb, e);
    if(!e->recv_timer){
        printf("endpoint_new: recv_timer failed\n");
        goto error_send_timer;
    }
    timer_set(e->recv_timer, WATCHDOG_TIMEOUT_S);

    result = sem_init(&e->sem, 0, 1);
    if(result==-1) {
        perror("endpoint_new: sem_init(sem)");
        goto error_recv_timer;
    }

    result = sem_init(&e->send_sem, 0, 1);
    if(result==-1) {
        perror("endpoint_new: sem_init(send_sem)");
        goto error_sem;
    }

    result = sem_init(&e->recv_sem, 0, 1);
    if(result==-1) {
        perror("endpoint_new: sem_init(recv_sem)");
        goto error_send_sem;
    }

    e->send_fifo = fifo_new(64);
    if(!e->send_fifo) {
        printf("endpoint_new: fifo_new\n");
        goto error_recv_sem;
    }

    // if(is_server)
    if(is_server){
        e->cfd = endpoint_accept(e, fd);
        if(e->cfd==-1){
            printf("endpoint_new: endpoint_accept\n");
            goto error_send_fifo;
        }
    } else {
        e->cfd = fd;
    }

    e->locked_out = 0;

    e->send_state = SEND_OPEN;
    e->send_locked_out = 0;

    e->recv_state = RECV_HEADER;
    e->recv_locked_out = 0;
    e->recv_packet_cb = recv_packet_cb;
    e->recv_cb_arg = recv_cb_arg;

    e->ev_cfd_r.data.ptr = &e->ed_cfd_r;
    e->ev_cfd_r.events = EPOLLIN | EPOLLET;
    e->ed_cfd_r.arg = e;
    e->ed_cfd_r.in_cb = process_recv2;
    e->ed_cfd_r.out_cb = NULL;

    e->ev_cfd_w.data.ptr = &e->ed_cfd_w;
    e->ev_cfd_w.events = EPOLLOUT | EPOLLET;
    e->ed_cfd_w.arg = e;
    e->ed_cfd_w.in_cb = NULL;
    e->ed_cfd_w.out_cb = process_send2;

    // add this object to the endpoints list
    e->le = endpoint_list_push(e);
    if(!e->le) {
        printf("endpoint_new: endpoint_list_push failed.\n");
        goto error_cfd;
    }


    // initailize SSL if requested

    // ADD to the read epoll instance interest list
    result = epoll_ctl(recv_epoll_fd, EPOLL_CTL_ADD, e->cfd, &e->ev_cfd_r);
    if(result==-1){
        perror("endpoint_new: epoll_ctl(ADD)");
        goto error_endpoint_list;
    }

    return e;
error_endpoint_list:
    endpoint_list_remove(e->le);
error_cfd:
    close(e->cfd);
error_send_fifo:
    fifo_delete(e->send_fifo);
error_recv_sem:
    sem_destroy(&e->recv_sem);
error_send_sem:
    sem_destroy(&e->send_sem);
error_sem:
    sem_destroy(&e->sem);
error_recv_timer:
    timer_destroy(e->recv_timer);
error_send_timer:
    timer_destroy(e->send_timer);
error_free:
    free(e);
    return NULL;
}

void endpoint_close(endpoint *e)
{
    // lockout the endpoint, read and write semaphores
    e->locked_out = 1;
    e->send_locked_out = 1;
    e->recv_locked_out = 1;
}

void endpoint_reap(endpoint *e)
{
    e->locked_out = 1;
    e->send_locked_out = 1;
    e->recv_locked_out = 1;

    int result;
    // wait on the endpoint semaphore
    result = sem_wait(&e->sem);
    if(result==-1){
        perror("endpoint_reap: sem_wait(sem)");
    }

    // DELete the file descriptor from the epoll interest lists
    epoll_ctl(send_epoll_fd, EPOLL_CTL_DEL, e->cfd, NULL);
    epoll_ctl(recv_epoll_fd, EPOLL_CTL_DEL, e->cfd, NULL);

    // wait on the read and write semaphores
    result = sem_wait(&e->send_sem);
    if(result==-1){
        perror("endpoint_reap: sem_wait(send_sem)");
    }

    result = sem_wait(&e->recv_sem);
    if(result==-1){
        perror("endpoint_reap: sem_wait(recv_sem)");
    }

    // free the resources in the object
    close(e->cfd);
    s_ptr *sp;
    while(sp = fifo_read(e->send_fifo)){
        shared_ptr_free(sp);
    }
    fifo_delete(e->send_fifo);
    sem_destroy(&e->recv_sem);
    sem_destroy(&e->send_sem);
    sem_destroy(&e->sem);
    timer_destroy(e->recv_timer);
    timer_destroy(e->send_timer);

    if(e->send_state==SEND_READY || e->send_state==SEND_INPROGRESS)
        shared_ptr_free(e->send_buf_s_ptr);

    if(e->recv_state==RECV_INPROGRESS)
        free(e->recv_buf_malloc);
}

void endpoint_send(endpoint *e, s_ptr *sp)
{
    if(e->locked_out){
        printf("endpoint_send: locked_out\n");
        shared_ptr_free(sp);
        return;
    }
    int r;
    sem_wait(&e->sem);
    if(fifo_empty(e->send_fifo)){
        if(e->send_locked_out){
            printf("endpoint_send: send_locked_out\n");
            shared_ptr_free(sp);
            sem_post(&e->sem);
            return;
        }
        sem_wait(&e->send_sem);
        if(e->send_state==SEND_OPEN){
            e->send_state = SEND_READY;
            e->send_buf_s_ptr = sp;
            e->send_buf = shared_ptr_data(sp);
            e->send_bytes = packet_length(e->send_buf);
            sem_post(&e->send_sem);
            process_send2(e);
            sem_post(&e->sem);
            return;
        }else{
            if(!fifo_write(e->send_fifo, sp)){
                shared_ptr_free(sp);
            }
            sem_post(&e->send_sem);
            sem_post(&e->sem);
            return;
        }
    }else{
        if(!fifo_write(e->send_fifo, sp)){
            shared_ptr_free(sp);
        }
        sem_post(&e->sem);
        return;
    }
}

int endpoint_count(void)
{
    return N_endpoints;
}

