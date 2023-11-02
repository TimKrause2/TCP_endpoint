#include "timer.h"
#include "protocol.h"
#include "fifo.h"
#include "shared_ptr.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/epoll.h>
#define __USE_GNU
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <semaphore.h>

typedef struct endpoint_s endpoint_t;
typedef void (*loop_func_ptr)(endpoint_t *, void *);
typedef void (*io_process)(void *);
typedef void (*dispatch_cb)(void *);
typedef struct epoll_dispatch epoll_dispatch;

struct epoll_dispatch
{
    void *arg;
    dispatch_cb in_cb;
    dispatch_cb out_cb;
};

struct endpoint_s
{
	int cfd;
	int recv_pipe[2];
	int send_pipe[2];
	int term_pipe[2];

    timer *send_timer;
    timer *recv_timer;
	pthread_t io_thread;

	io_process process_send_cb;
	int    send_state;
    char  *send_buf_malloc;
	char  *send_buf;
	size_t send_bytes;

	io_process process_recv_cb;
	int    recv_state;
	char  *recv_buf_malloc;
	char  *recv_buf;
	size_t recv_bytes;

    int epfd;
	struct epoll_event ev_cfd_r;
	struct epoll_event ev_cfd_rw;
	struct epoll_event ev_send;
	struct epoll_event ev_term;
    struct epoll_dispatch ed_cfd;
    struct epoll_dispatch ed_send;
    struct epoll_dispatch ed_term;

	unsigned int ssl_enable:1;
	unsigned int server:1;
    unsigned int io_terminate:1;

	SSL_CTX *ssl_ctx;
	SSL     *ssl;
};

enum {
    SEND_OPEN, // interface is available
    SEND_READY, // buffers have been initialized
    SEND_INPROGRESS, // packet transmission is in progress
    SEND_VERIFY, // packet has been transmitted and wainting for final
	SEND_ERROR
};

enum {
	RECV_HEADER,
	RECV_INPROGRESS,
	RECV_ERROR
};

void endpoint_process(
		int cfd,
		loop_func_ptr loop_func,
		void *arg,
		int ssl_enable,
		int server);
void io_shutdown(endpoint_t *e);
void socket_set_nonblock(int fd, int nonblock);

typedef struct endpoint endpoint;
typedef struct endpoint_list_element ele;
typedef struct call_args_list_element cale;
typedef struct call_args_list_struct  cals;
typedef struct thread_data_struct tds;

struct endpoint
{
    int cfd;
    struct sockaddr_storage peer_addr;
    sem_t  sem;
    int locked_out;

    ele *le;

    timer *send_timer;
    timer *recv_timer;

    int     send_state;
    sem_t   send_sem;
    int     send_locked_out;
    s_ptr  *send_buf_s_ptr;
    char   *send_buf;
    size_t  send_bytes;
    fifo_t *send_fifo;

    int    recv_state;
    sem_t  recv_sem;
    int    recv_locked_out;
    char  *recv_buf_malloc;
    char  *recv_buf;
    size_t recv_bytes;
    void (*recv_packet_cb)(void *packet, endpoint *e);
    void  *recv_cb_arg;

    struct epoll_event ev_cfd_r;
    struct epoll_event ev_cfd_w;
    struct epoll_dispatch ed_cfd_r;
    struct epoll_dispatch ed_cfd_w;

    unsigned int ssl_enable:1;
    unsigned int server:1;

    SSL_CTX *ssl_ctx;
    SSL     *ssl;
};

struct endpoint_list_element
{
    endpoint *e;
    ele *next;
    ele *prev;
};

struct call_args_list_element
{
    endpoint *e;
    void *packet;
    cale *next;
};

struct call_args_list_struct
{
    cale *head;
    cale *tail;
};

struct thread_data_struct
{
    int num;
    pthread_t thread;
};

int endpoints_init(int N_send_threads_in, int N_recv_threads_in);

endpoint *endpoint_new(int fd,
        void (*recv_packet_cb)(void *packet, endpoint *e),
        void *recv_cb_arg,
        int ssl_enabled,
        int is_server);

void endpoint_close(endpoint *e);
void endpoint_send(endpoint *e, s_ptr *sp);
int  endpoint_count(void);

extern ele *el_head;
void endpoint_list_lock(void);
void endpoint_list_unlock(void);

