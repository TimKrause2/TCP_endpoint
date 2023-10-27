#include "timer.h"
#include "protocol.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>

typedef struct endpoint_s endpoint_t;
typedef void (*loop_func_ptr)(endpoint_t *, void *);
typedef void (*io_process)(void *);
typedef void (*dispatch_cb)(void *);

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
	SEND_READY,
	SEND_INPROGRESS,
	SEND_VERIFY,
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
