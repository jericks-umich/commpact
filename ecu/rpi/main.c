
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "commpact_types.h"
#include "cp_crypto.h"
#include "ecu_types.h"

#define IPADDR "192.168.1.147"
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

ecu_message_t state[MAX_VEHICLES];
cp_ec256_private_t priv_keypair[MAX_VEHICLES];
cp_ec256_public_t pub_keypair[MAX_VEHICLES];
cp_ec256_public_t pubkeys[MAX_VEHICLES];
// int mode; // either setup or running

commpact_status_t generateKeyPair(uint8_t position) {

  int retval = 0;
  commpact_status_t status = CP_SUCCESS;
  void *ecc_handle;

  status = cp_ecc256_open_context(&ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu open ec256 context failed\n");
    return status;
  }

  status = cp_ecc256_create_key_pair(&priv_keypair[position],
                                     &pub_keypair[position], ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu generate ec256 key pair failed\n");
    cp_ecc256_close_context(ecc_handle);
    return status;
  }

  status = cp_ecc256_close_context(ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu close ec256 context failed\n");
    return status;
  }

  return status;
}

commpact_status_t signMessage(uint8_t position, ecu_message_t *message,
                              cp_ec256_signature_t *signature) {
  int retval = 0;
  void *ecc_handle;
  commpact_status_t status = CP_SUCCESS;

  // Open ecc256 context
  status = cp_ecc256_open_context(&ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: open ecc256 context failed\n");
    return status;
  }

  status = (commpact_status_t)cp_ecdsa_sign(
      (uint8_t *)message, sizeof(ecu_message_t), &priv_keypair[position],
      signature, ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: Signing failed\n");
    cp_ecc256_close_context(ecc_handle);
    return status;
  }

  status = cp_ecc256_close_context(ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: close ecc256 context failed\n");
    return status;
  }

  return CP_SUCCESS;
}

commpact_status_t verifyMessage(uint8_t position,
                                cp_ec256_signature_t *enclave_signature,
                                ecu_message_t *message) {

  uint8_t verify_result = 0;
  void *ecc_handle;
  commpact_status_t status = CP_SUCCESS;

  // Open ecc256 context
  status = cp_ecc256_open_context(&ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: open ecc256 context failed\n");
    return status;
  }

  cp_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t), &pubkeys[position],
                  enclave_signature, &verify_result, ecc_handle);

  if (verify_result != CP_EC_VALID) {
    printf("ERROR: cannot validate signature\n");
    cp_ecc256_close_context(ecc_handle);
    exit(1);
    return CP_ERROR;
  }

  status = cp_ecc256_close_context(ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: close ecc256 context failed\n");
    return status;
  }

  return CP_SUCCESS;
}

// if in setup mode, add this pubkey to our list
// if in running mode, reset to setup mode, clear pubkeys, and add new one to
// list
void handle_pubkey(uint8_t position, uint8_t *buf, int *nbytes) {
  commpact_status_t status;
  // check if we have enough bytes
  if (*nbytes < 2 + sizeof(cp_ec256_public_t)) {
    printf("not enough data for a pubkey\n");
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }
  // if (mode == MODE_RUNNING) {
  //  // wipe state
  //  memset(priv_keypair, 0, MAX_VEHICLES * sizeof(cp_ec256_private_t));
  //  memset(pub_keypair, 0, MAX_VEHICLES * sizeof(cp_ec256_public_t));
  //  memset(pubkeys, 0, MAX_VEHICLES * sizeof(cp_ec256_public_t));
  //  mode = MODE_SETUP;
  //}
  // add pubkey to list
  memcpy(&pubkeys[position], buf + 2, sizeof(cp_ec256_public_t));
  // generate new keypair
  status = generateKeyPair(position);
  if (status != CP_SUCCESS) {
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }
  // return new pubkey
  *nbytes = sizeof(cp_ec256_public_t);
  memcpy(buf, &pub_keypair[position], *nbytes);
}

// if in running mode, verify signature, copy message into memory, sign response
// if in setup mode, start running mode and do the above
void handle_message(uint8_t position, uint8_t *buf, int *nbytes) {
  commpact_status_t status;
  // check if we have enough bytes
  if (*nbytes < 2 + sizeof(ecu_message_t) + sizeof(cp_ec256_signature_t)) {
    printf("not enough data for a message and signature\n");
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }
  // mode = MODE_RUNNING; // no need to check if its in setup or running mode,
  // it's
  // faster not to branch and to just set it every time
  ecu_message_t *msg_ptr = (ecu_message_t *)(buf + 2);
  // verify signature
  // memcpy(sig, buf+2+sizeof(ecu_message_t), sizeof(cp_ec256_signature_t));
  cp_ec256_signature_t *sig =
      (cp_ec256_signature_t *)(buf + 2 + sizeof(ecu_message_t));
  // printf("attempting verify\n");
  // printf("pubkey at position %u: ", position);
  // for (int i = 0; i < sizeof(cp_ec256_public_t); i++) {
  //  printf("%02x", ((uint8_t *)&pubkeys[position])[i]);
  //}
  // printf("\n");
  // printf("signature: ");
  // for (int i = 0; i < sizeof(cp_ec256_signature_t); i++) {
  //  printf("%02x", ((uint8_t *)sig)[i]);
  //}
  // printf("\n");
  // printf("message: ");
  // for (int i = 0; i < sizeof(ecu_message_t); i++) {
  //  printf("%02x", ((uint8_t *)msg_ptr)[i]);
  //}
  // printf("\n");
  status = verifyMessage(position, sig, msg_ptr);
  if (status != CP_SUCCESS) { // verify failed
    printf("verify failed\n");
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }
  // printf("verify succeeded\n");
  // copy message into memory
  state[position] = *msg_ptr;
  // sign response
  status = signMessage(position, msg_ptr, (cp_ec256_signature_t *)buf);
  if (status != CP_SUCCESS) { // sign failed
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }
  // return signature
  *nbytes = sizeof(cp_ec256_signature_t);
  // memcpy(buf, &sig, *nbytes); // signature written directly into buf
}

// parses the supplied buffer and sets the buffer to the value that should be
// returned
void parse(uint8_t *buf, int *nbytes) {
  uint8_t type, position;

  if (*nbytes < 2) { // not enough data
    printf("not enough data\n");
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }

  type = buf[0];
  position = buf[1];

  if (position > MAX_VEHICLES - 1) { // if position is invalid
    printf("invalid vehicle position\n");
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }

  if (type == 1) { // pubkey type
    handle_pubkey(position, buf, nbytes);
  } else if (type == 0) { // message type
    handle_message(position, buf, nbytes);
  } else {
    printf("invalid type\n");
    *nbytes = BUF_SIZE;
    memset(buf, 0, *nbytes);
    return;
  }
}

int main() {
  struct sockaddr_in addr, cli_addr;
  int listenfd, connfd, clilen, nbytes;
  uint8_t buf[BUF_SIZE];

  // set mode to setup initially
  // mode = MODE_SETUP;

  // set up listening socket
  listenfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (listenfd < 0) {
    printf("couldn't open listening socket\n");
    return -1;
  };
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, IPADDR, &(addr.sin_addr));
  addr.sin_port = htons(PORT);
  if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr))) {
    printf("couldn't bind to %s:%d\n", IPADDR, PORT);
    return -1;
  }
  listen(listenfd, 1);

  clilen = sizeof(cli_addr);
  while (1) {
    // handle an incoming packet
    nbytes = recvfrom(listenfd, buf, BUF_SIZE, 0, (struct sockaddr *)&cli_addr,
                      &clilen);
    // printf("received packet:");
    // for (int i = 0; i < nbytes; i++) {
    //  printf("%02x", buf[i]);
    //}
    // printf("\n");
    if (nbytes < 0) {
      printf("error reading data\n");
      return -3;
    }

    // parse data
    parse(buf, &nbytes);

    // return result
    nbytes =
        sendto(listenfd, buf, nbytes, 0, (struct sockaddr *)&cli_addr, clilen);
    if (nbytes < 0) {
      printf("error writing data\n");
      return -5;
    }
    // printf("sent packet\n");
  }
}
