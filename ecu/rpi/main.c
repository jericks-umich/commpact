
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "commpact_types.h"
#include "ecu_types.h"

#define IPADDR "127.0.0.1"
#define PORT 9999
#define BUF_SIZE 256
#define MAX_VEHICLES 8

#define MODE_SETUP 0
#define MODE_RUNNING 1

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

cp_ec256_private_t priv_keypair[MAX_VEHICLES];
cp_ec256_public_t pub_keypair[MAX_VEHICLES];
cp_ec256_public_t pubkeys[MAX_VEHICLES];
int mode; // either setup or running

// parses the supplied buffer and sets the buffer to the value that should be returned
void parse(uint8_t* buf, int *nbytes) {
	uint8_t type, position;
	type = buf[0];
	position = buf[1];

	if (position > MAX_VEHICLES - 1) { // if position is invalid
		printf("invalid vehicle position\n");
		*nbytes = BUF_SIZE;
		memcpy(buf, 0, *nbytes);
		return;
	}


	if (type == 1) { // pubkey type
	}
	else if (type == 0) { // message type
	}
	else {
		printf("invalid type\n");
		*nbytes = BUF_SIZE;
		memcpy(buf, 0, *nbytes);
		return;
	}

}


int main() {
  struct sockaddr_in addr, cli_addr;
  int listenfd, connfd, clilen, nbytes;
  uint8_t buf[BUF_SIZE];

	// set

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

	while (1) {

  // handle an incoming packet
  clilen = sizeof(cli_addr);
	nbytes = recvfrom(listenfd, buf, BUF_SIZE, 0, (struct sockaddr*) &cli_addr, &clilen);
  if (nbytes < 0) {
    printf("error reading data\n");
    return -3;
  }

  // parse data
	parse(buf, &nbytes);

  // return result
  nbytes = sendto(listenfd, buf, nbytes, 0, (struct sockaddr*) &cli_addr, clilen);
  if (nbytes < 0) {
    printf("error writing data\n");
    return -5;
  }
	}
}
