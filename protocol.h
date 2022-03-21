#ifndef PROTOCOL_H
#define PROTOCOL_H


#define WATCHDOG_TIMEOUT_S 10
#define CONFIRM_TIMEOUT_S  5

enum {
	P_STATUS,
	P_DATA,
};

struct packet_common
{
	unsigned char type; // type of packet P_STATUS or P_DATA
	unsigned char code; // code
	unsigned int  length; // total length of the packet including packet_common
};

struct packet_status
{
	struct packet_common header;
};

enum {
	P_ST_CODE_READY,
	P_ST_CODE_BUSY,
	P_ST_CODE_CONFIRM
};

char *packet_status_new(unsigned char code);

struct packet_data
{
	struct packet_common header;
	char data[];
};

char *packet_data_new(char *data, int nbytes);

#endif
