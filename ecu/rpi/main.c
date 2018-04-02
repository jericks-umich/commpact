
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define IPADDR "127.0.0.1"
#define PORT 9999
#define BUF_SIZE 256

// This program serves as an emulated ECU in our simulation.
// It will be run on a Raspberry Pi, connected to our simulation server via
// ethernet. This ECU should open a UDP listening socket, accept connections
// to
// it, and treat each new connection as a new simulation.

// To start, each vehicle will send the ECU its pubkey. The ECU should
// generate
// its own keypair for each pubkey it receives, and return its corresponding
// pubkey.

// Later, the ECU will receive messages and signatures, and should verify
// these
// signatures, then sign the message itself and return the new signature.

int main() {
  struct sockaddr_in addr, cli_addr;
  int listenfd, connfd, clilen, nbytes;
  uint8_t buf[BUF_SIZE];

  // set up listening socket
  listenfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (listenfd < 0) {
    printf("couldn't open listening socket\n");
    return -1;
  };
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, IPADDR, &(addr.sin_addr));
  addr.sin_port = htons(PORT);
  if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr))) {
    printf("couldn't bind to %s:%d\n", IPADDR, PORT);
    return -1;
  }
  listen(listenfd, 1);

  // handle a client connection
  clilen = sizeof(cli_addr);
  connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &clilen);
  if (connfd < 0) {
    printf("couldn't open connection socket\n");
    return -2;
  }

  // read data
  nbytes = read(connfd, buf, BUF_SIZE - 1);
  if (nbytes < 0) {
    printf("error reading data\n");
    return -3;
  }

  // parse data

  // return result
  nbytes = write(connfd, buf, nbytes);
  if (nbytes < 0) {
    printf("error writing data\n");
    return -5;
  }
}
