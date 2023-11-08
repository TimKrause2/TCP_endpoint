#include "endpoint.h"
#include "util.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>

#define SOCKET_PATH "\0tims.server.socket"

sem_t finish_sem;

enum {
    C_STATE_NONE,
    C_STATE_SERVER_INFO,
    C_STATE_ENDPOINT_LIST
};

static int c_state = C_STATE_SERVER_INFO;

static endpoint_info *endpoint_list;
static endpoint_info *endpoint_list_w;
static long N_endpoints;
static long N_endpoints_recv;
static struct timespec server_ts;
static struct timespec now_ts;

void recv_packet_cb(void *packet, endpoint *e)
{
    //printf("recv_packet_cb:\n");
    switch(c_state){
    case C_STATE_SERVER_INFO:
        if(packet_get_type(packet)==P_DATA
                && packet_get_code(packet)==P_DATA_CODE_SERVER_INFO)
        {
            //printf("recv_packet_cb: server_info\n");
            server_info *info = (server_info*)packet_data_get_data(packet);
            N_endpoints = info->N_endpoints;
            memcpy(&server_ts, &info->server_ts, sizeof(struct timespec));
            endpoint_list = malloc(N_endpoints*sizeof(endpoint_info));
            endpoint_list_w = endpoint_list;
            N_endpoints_recv = 0;
            c_state = C_STATE_ENDPOINT_LIST;
        }
        break;
    case C_STATE_ENDPOINT_LIST:
        if(packet_get_type(packet)==P_DATA
                && packet_get_code(packet)==P_DATA_CODE_ENDPOINT_INFO)
        {
            //printf("recv_packet_cb: endpoint_info\n");
            endpoint_info *info = (endpoint_info*)packet_data_get_data(packet);
            if(endpoint_list)
                memcpy(endpoint_list_w, info, sizeof(endpoint_info));
            N_endpoints_recv++;
            if(N_endpoints_recv == N_endpoints){
                printf("recv_packet_cb: endpoint list complete.\n");
                c_state = C_STATE_NONE;
                sem_post(&finish_sem);
            }
            endpoint_list_w++;
        }
        break;
    default:
        printf("recv_packet_cb: some other packet.\n");
        break;
    }
    free(packet);
}

void print_endpoint_list(void)
{
    printf("Server uptime:");
    print_elapsed(&now_ts, &server_ts);
    printf("\n");
    if(!endpoint_list){
        printf("Couldn't allocate memory for endpoint list.\n");
        return;
    }
    printf("Endpoint list:\n");
    for(long i=0;i<N_endpoints;i++)
    {
        printf("endpoint %ld\n", i);
        printf("\tPeer Address:\n");
        print_sockaddr(&endpoint_list[i].peer_addr);
        printf("\tUptime:");
        print_elapsed(&now_ts, &endpoint_list[i].init_ts);
        printf("\n");
        printf("\tBytes sent:%ld received:%ld receive discarded:%ld\n",
               endpoint_list[i].send_sent,
               endpoint_list[i].recv_received,
               endpoint_list[i].recv_discarded);
    }
}

int main(int argc, char **argv)
{
    if(!timer_init()){
        printf("Couldn't initialize the timer subsystem.\n");
        exit(1);
    }

    if(!endpoints_init(1, 1)){
        printf("Couldn't initialize the endpoint subsystem.\n");
        exit(1);
    }

    int sfd;
    int result;
    struct sockaddr_un addr;

    result = sem_init(&finish_sem, 0, 0);
    if(result==-1){
        perror("sem_init(finish_sem)");
        exit(1);
    }

    sfd = socket( AF_UNIX, SOCK_STREAM, 0 );
    if( sfd == -1 ){
        perror( "socket" );
        exit( 1 );
    }

    socklen_t addr_len = sockaddr_un_prepare(&addr, SOCKET_PATH);

    result = connect( sfd, (const struct sockaddr*)&addr, addr_len );
    if( result == -1 ){
        perror( "connect" );
        exit( 1 );
    }

    socket_set_nonblock(sfd, 1);

    endpoint *e = endpoint_new(sfd, recv_packet_cb, NULL, 0, 0);
    char *packet = packet_command_new(P_CMD_CODE_ENDPOINT_LIST);
    if(!packet){
        printf("Couldn't allocate the command packet.\n");
        exit(1);
    }

    s_ptr *sp = shared_ptr_new(packet);
    if(!sp){
        printf("Couldn't allocate the shared pointer.\n");
        exit(1);
    }

    endpoint_send(e, sp);

    sem_wait(&finish_sem);
    clock_gettime(CLOCK_REALTIME, &now_ts);
    print_endpoint_list();
    exit(0);
}
