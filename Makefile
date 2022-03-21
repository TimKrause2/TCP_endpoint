LDFLAGS= -pthread -ggdb
LDLIBS=-lrt -lssl -lcrypto
CFLAGS= -pthread -ggdb

all: server client

server:server.o protocol.o timer.o endpoint.o

client:client.o protocol.o timer.o endpoint.o

client.o:client.c

endpoint.o:endpoint.c

server.o:server.c

protocol.o:protocol.c

timer.o:timer.c
