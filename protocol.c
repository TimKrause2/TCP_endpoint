#include "protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <endian.h>

/* CRC-32C (iSCSI) polynomial in reversed bit order. */
#define POLY 0x82f63b78

/* CRC-32 (Ethernet, ZIP, etc.) polynomial in reversed bit order. */
/* #define POLY 0xedb88320 */

uint32_t crc32c(uint32_t crc, const unsigned char *buf, size_t len)
{
    int k;

    crc = ~crc;
    while (len--) {
        crc ^= *buf++;
        for (k = 0; k < 8; k++)
            crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    }
    return ~crc;
}

uint16_t extract_short(char *data, int offset)
{
    uint16_t x;
    memcpy(&x, &data[offset], 2);
    return x;
}

void insert_short(char *data, int offset, uint16_t x)
{
    memcpy(&data[offset], &x, 2);
}

uint32_t extract_int(char *data, int offset)
{
    uint32_t x;
    memcpy(&x, &data[offset], 4);
    return x;
}

void insert_int(char *data, int offset, uint32_t x)
{
    memcpy(&data[offset], &x, 4);
}

uint64_t extract_long(char *data, int offset)
{
    uint64_t x;
    memcpy(&x, &data[offset], 8);
    return x;
}

void insert_long(char *data, int offset, uint64_t x)
{
    memcpy(&data[offset], &x, 8);
}

void packet_set_type(char *packet, uint16_t type)
{
    insert_short(packet, OFFSET_OF_TYPE, htobe16(type));
}

uint16_t packet_get_type(char *packet)
{
    return be16toh(extract_short(packet, OFFSET_OF_TYPE));
}

void packet_set_code(char *packet, uint16_t code)
{
    insert_short(packet, OFFSET_OF_CODE, htobe16(code));
}

uint16_t packet_get_code(char *packet)
{
    return be16toh(extract_short(packet, OFFSET_OF_CODE));
}

void packet_set_length(char *packet, uint32_t length)
{
    insert_int(packet, OFFSET_OF_LENGTH, htobe32(length));
}

uint32_t packet_get_length(char *packet)
{
    return be32toh(extract_int(packet, OFFSET_OF_LENGTH));
}

void packet_set_crc(char *packet, uint32_t crc)
{
    insert_int(packet, OFFSET_OF_CRC, htobe32(crc));
}

uint32_t packet_get_crc(char *packet)
{
    return be32toh(extract_int(packet, OFFSET_OF_CRC));
}

void packet_seal(char *packet)
{
    uint32_t crc = crc32c(0, packet, SIZEOF_PACKET_CRC_DATA);
    packet_set_crc(packet, crc);
}

int packet_ok(char *packet)
{
    uint32_t crc = crc32c(0, packet, SIZEOF_PACKET_CRC_DATA);
    return crc == packet_get_crc(packet)?1:0;
}

char *packet_status_new(uint16_t code)
{
    char *ps = malloc(SIZEOF_PACKET_COMMON);
    if(!ps){
        perror("packet_status_new:malloc");
        return NULL;
    }
    packet_set_type(ps, P_STATUS);
    packet_set_code(ps, code);
    packet_set_length(ps, SIZEOF_PACKET_COMMON);
    packet_seal(ps);
    return ps;
}

char *packet_command_new(uint16_t code)
{
    char *ps = malloc(SIZEOF_PACKET_COMMON);
    if(!ps){
        perror("packet_status_new:malloc");
        return NULL;
    }
    packet_set_type(ps, P_COMMAND);
    packet_set_code(ps, code);
    packet_set_length(ps, SIZEOF_PACKET_COMMON);
    packet_seal(ps);
    return ps;
}

char *packet_data_new(char *data, int nbytes, uint16_t code)
{
    size_t total_bytes = SIZEOF_PACKET_COMMON + nbytes;
    char *pd = malloc(total_bytes);
	if(!pd){
		perror("packet_data_new:malloc");
		return NULL;
	}
    packet_set_type(pd, P_DATA);
    packet_set_code(pd, code);
    packet_set_length(pd, total_bytes);
    packet_seal(pd);
    memcpy(&pd[OFFSET_OF_DATA], data, nbytes);
    return pd;
}

char *packet_data_get_data(char *packet)
{
    return &packet[OFFSET_OF_DATA];
}

int packet_data_get_nbytes(char *packet)
{
    return packet_get_length(packet) - SIZEOF_PACKET_COMMON;
}

char *packet_endpoint_info_new(
        struct sockaddr_storage *peer_addr,
        struct timespec *init_ts,
        long send_sent,
        long recv_received,
        long recv_discarded)
{
    endpoint_info info;
    memcpy(&info.peer_addr, peer_addr, sizeof(struct sockaddr_storage));
    memcpy(&info.init_ts, init_ts, sizeof(struct timespec));
    info.send_sent = send_sent;
    info.recv_received = recv_received;
    info.recv_discarded = recv_discarded;
    char *packet = packet_data_new((char*)&info, sizeof(info), P_DATA_CODE_ENDPOINT_INFO);
    return packet;
}

char *packet_server_info_new(
        struct timespec *server_ts,
        long N_endpoints)
{
    server_info info;
    memcpy(&info.server_ts, server_ts, sizeof(struct timespec));
    info.N_endpoints = N_endpoints;
    char *packet = packet_data_new((char*)&info, sizeof(info), P_DATA_CODE_SERVER_INFO);
    return packet;
}

