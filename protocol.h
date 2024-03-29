#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <arpa/inet.h>

#define WATCHDOG_TIMEOUT_S 10
#define CONFIRM_TIMEOUT_S  5

enum {
	P_STATUS,
	P_DATA,
    P_COMMAND,
};

#define SIZEOF_PACKET_COMMON  16
#define SIZEOF_PACKET_CRC_DATA 8
#define OFFSET_OF_TYPE   0
#define OFFSET_OF_CODE   2
#define OFFSET_OF_LENGTH 4
#define OFFSET_OF_CRC    8

void packet_set_type(char *packet, uint16_t type);
uint16_t packet_get_type(char *packet);
void packet_set_code(char *packet, uint16_t code);
uint16_t packet_get_code(char *packet);
void packet_set_length(char *packet, uint32_t length);
uint32_t packet_get_length(char *packet);
void packet_set_crc(char *packet, uint32_t crc);
uint32_t packet_get_crc(char *packet);
void packet_seal(char *packet);
int packet_ok(char *packet);

enum {
	P_ST_CODE_READY,
	P_ST_CODE_BUSY,
	P_ST_CODE_CONFIRM
};

enum {
    P_CMD_CODE_SERVER_INFO,
    P_CMD_CODE_ENDPOINT_LIST
};

enum {
    P_DATA_CODE_RAW_DATA=0,
    P_DATA_CODE_SERVER_INFO,
    P_DATA_CODE_ENDPOINT_INFO
};

char *packet_status_new(uint16_t code);
char *packet_command_new(uint16_t code);

#define OFFSET_OF_DATA SIZEOF_PACKET_COMMON

char *packet_data_new(char *data, int nbytes, uint16_t code);
char *packet_data_get_data(char *packet);
int   packet_data_get_nbytes(char *packet);

typedef struct endpoint_info endpoint_info;
typedef struct server_info server_info;

struct endpoint_info
{
    struct sockaddr_storage peer_addr;
    struct timespec         init_ts;
    long                    send_sent;
    long                    recv_received;
    long                    recv_discarded;
};

char *packet_endpoint_info_new(
    struct sockaddr_storage *peer_addr,
    struct timespec *init_ts,
    long send_sent,
    long recv_received,
    long recv_discarded);

struct server_info
{
    struct timespec  server_ts;
    long             N_endpoints;
};

char *packet_server_info_new(
        struct timespec *server_ts,
        long N_endpoints);










#endif
