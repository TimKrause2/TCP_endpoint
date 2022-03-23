# TCP_endpoint

## Description

Demonstrates using the, Linux specific, epoll interface to wait on file descriptors of
sockets and pipes. Also utilizes non-blocking io, and SSL encryption if desired.

## Compilation

Change to the directory. Then type `make`.

## Execution

For SSL operation two files need to be present in the working directory. These
files are usually links to the actual files. The two files are `fullchain.pem`
and `privkey.pem`. `fullchain.pem` contains the server certificate and the
chain of signing certificates all the way to the root certificate. `privkey.pem`
contains the private key in PEM format.

To run the server type

`./server <service or port>`

To run the client type

`./client <host> <service or port>`


