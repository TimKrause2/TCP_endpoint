#include "protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

void packet_set_type(char *packet, uint16_t type)
{
    *(uint16_t*)&packet[OFFSET_OF_TYPE] = htons(type);
}

uint16_t packet_get_type(char *packet)
{
    return ntohs(*(uint16_t*)&packet[OFFSET_OF_TYPE]);
}

void packet_set_code(char *packet, uint16_t code)
{
    *(uint16_t*)&packet[OFFSET_OF_CODE] = htons(code);
}

uint16_t packet_get_code(char *packet)
{
    return ntohs(*(uint16_t*)&packet[OFFSET_OF_CODE]);
}

void packet_set_length(char *packet, uint32_t length)
{
    *(uint32_t*)&packet[OFFSET_OF_LENGTH] = htonl(length);
}

uint32_t packet_get_length(char *packet)
{
    return ntohl(*(uint32_t*)&packet[OFFSET_OF_LENGTH]);
}

void packet_set_crc(char *packet, uint32_t crc)
{
    *(uint32_t*)&packet[OFFSET_OF_CRC] = htonl(crc);
}

uint32_t packet_get_crc(char *packet)
{
    return ntohl(*(uint32_t*)&packet[OFFSET_OF_CRC]);
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

char *packet_data_new(char *data, int nbytes)
{
    size_t total_bytes = SIZEOF_PACKET_COMMON + nbytes;
    char *pd = malloc(total_bytes);
	if(!pd){
		perror("packet_data_new:malloc");
		return NULL;
	}
    packet_set_type(pd, P_DATA);
    packet_set_code(pd, 0);
    packet_set_length(pd, total_bytes);
    memcpy(&pd[OFFSET_OF_DATA], data, nbytes);
    packet_seal(pd);
    return pd;
}

void *packet_data_get_data(char *packet)
{
    return (void *)&packet[OFFSET_OF_DATA];
}

int packet_data_get_nbytes(char *packet)
{
    return packet_get_length(packet) - SIZEOF_PACKET_COMMON;
}
