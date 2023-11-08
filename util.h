#include <time.h>
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

void random_init(void);
int random_range(int lo, int hi);
void millisleep(int milli_seconds);

void timespec_diff(struct timespec *t1, struct timespec *t0, struct timespec *r);
void print_elapsed(struct timespec *now, struct timespec *then);

void print_sockaddr(struct sockaddr_storage *ss);

size_t sockaddr_un_prepare(struct sockaddr_un *sa, char *path);
