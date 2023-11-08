LDFLAGS= -pthread -ggdb
LDLIBS=-lrt -lssl -lcrypto -lm
CFLAGS= -pthread -ggdb

all: server2 client2 svrctl

server2:server2.o protocol.o timer.o endpoint.o fifo.o shared_ptr.o util.o

client2:client2.o protocol.o timer.o endpoint.o fifo.o shared_ptr.o util.o

svrctl:svrctl.o protocol.o timer.o endpoint.o fifo.o shared_ptr.o util.o

server:server.o protocol.o timer.o endpoint.o fifo.o shared_ptr.o

client:client.o protocol.o timer.o endpoint.o fifo.o shared_ptr.o

client.o:client.c

client2.o:client2.c

endpoint.o:endpoint.c

server.o:server.c

server2.o:server2.c

protocol.o:protocol.c

timer.o:timer.c

fifo.o:fifo.c

shared_ptr.o:shared_ptr.c

util.o:util.c

svrctl.o:svrctl.c
