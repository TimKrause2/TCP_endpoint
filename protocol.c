#include "protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char *packet_status_new(unsigned char code)
{
	struct packet_status *ps = malloc(sizeof(struct packet_status));
	if(!ps){
		perror("packet_status_new:malloc");
		return NULL;
	}
	ps->header.type = P_STATUS;
	ps->header.code = code;
	ps->header.length = sizeof(struct packet_status);
	return (char *)ps;
}

char *packet_data_new(char *data, int nbytes)
{
	size_t total_bytes = sizeof(struct packet_common) + nbytes;
	struct packet_data *pd = malloc(total_bytes);
	if(!pd){
		perror("packet_data_new:malloc");
		return NULL;
	}
	pd->header.type = P_DATA;
	pd->header.code = 0;
	pd->header.length = total_bytes;
	memcpy(pd->data, data, nbytes);
	return (char *)pd;
}

unsigned int packet_length(void *packet)
{
    struct packet_common *h = (struct packet_common*)packet;
    return h->length;
}

