#include "ecu.h"
#include "initialsetup.h"

#include "sgx_tcrypto.h"

#include <stdlib.h>

///////////////////////
// GLOBAL PARAMETERS //
///////////////////////
int sockfd;
// ecu_message_t ecu_parameters;
// cp_ec256_public_t enclave_pub_key;
// cp_ec256_private_t ecu_priv_key;
// cp_ec256_public_t ecu_pub_key;

// map index is platoon position
// std::unordered_map<uint64_t, ecu_t> ecus;
ecu_t ecus[COMMPACT_MAX_ENCLAVES];

commpact_status_t setEnclavePubKey(uint8_t position,
                                   cp_ec256_public_t *pub_key) {
  ecu_t *ecu = &ecus[position];
  memcpy(&(ecu->enclave_pub_key), pub_key, sizeof(cp_ec256_public_t));
  return CP_SUCCESS;
}
commpact_status_t setEnclavePubKeyRealECU(uint8_t position,
                                          cp_ec256_public_t *pub_key) {
  // clang-format off
  // msg type | position | public_key
  // one byte | one byte | sizeof(cp_ec256_public_t)
  // clang-format on
  uint64_t msg_len = 2 + +sizeof(cp_ec256_public_t);
  uint8_t buf[msg_len];
  memset(buf, 0, msg_len);
  buf[0] = ECU_SOCK_PUB_KEY_TYPE;
  buf[1] = position;
  memcpy(buf + 2, pub_key, sizeof(cp_ec256_public_t));
  if (send(sockfd, buf, msg_len, 0) == -1) {
    printf("error sending ecu message to real ecu\n");
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

commpact_status_t setParametersECU(uint8_t position,
                                   cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature) {

  uint8_t verify_result = 0;
  void *handle;
  ecu_t *ecu = &ecus[position];
  sgx_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t),
                   (sgx_ec256_public_t *)&(ecu->enclave_pub_key),
                   (sgx_ec256_signature_t *)enclave_signature, &verify_result,
                   handle);

  if (verify_result != CP_EC_VALID) {
    memset(ecu_signature, 0, sizeof(cp_ec256_signature_t));
    return CP_SUCCESS;
  }
  memcpy(&(ecu->ecu_parameters), message, sizeof(ecu_message_t));

  // Sign the message
  signMessage(ecu, message, ecu_signature);

  return CP_SUCCESS;
}

commpact_status_t generateKeyPair(uint8_t position,
                                  cp_ec256_public_t *pub_key) {

  int retval = 0;
  sgx_status_t status = SGX_SUCCESS;
  void *ecc_handle;
  ecu_t *ecu = &ecus[position];

  status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: ecu open ec256 context failed");
    return CP_ERROR;
  }

  status = sgx_ecc256_create_key_pair(
      (sgx_ec256_private_t *)&(ecu->ecu_priv_key),
      (sgx_ec256_public_t *)&(ecu->ecu_pub_key), ecc_handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: ecu generate ec256 key pair failed");
    return CP_ERROR;
  }

  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: ecu close ec256 context failed");
    return CP_ERROR;
  }

  memcpy(pub_key, &(ecu->ecu_pub_key), sizeof(cp_ec256_public_t));
  return CP_SUCCESS;
}

commpact_status_t signMessage(ecu_t *ecu, ecu_message_t *message,
                              cp_ec256_signature_t *signature) {
  int retval = 0;
  void *handle;
  sgx_status_t status = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: open ecc256 context failed");
    return CP_ERROR;
  }

  status = sgx_ecdsa_sign((uint8_t *)message, sizeof(ecu_message_t),
                          (sgx_ec256_private_t *)&(ecu->ecu_priv_key),
                          (sgx_ec256_signature_t *)signature, handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: Signing failed");
    return CP_ERROR;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: close ecc256 context failed");
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

commpact_status_t setParametersRealECU(uint8_t position,
                                       cp_ec256_signature_t *enclave_signature,
                                       ecu_message_t *message,
                                       cp_ec256_signature_t *ecu_signature) {
  uint64_t msg_len = 2 + sizeof(ecu_message_t) + sizeof(cp_ec256_signature_t);
  uint8_t buf[msg_len];
  memset(buf, 0, msg_len);
  // clang-format off
          // MSG should look like: msg_type | vehicle position | message               |enclave_signature
          //                       1 byte   | byte             | sizeof(ecu_message_t) |sizeof(cp_ec256_signature_t)
  // clang-format on
  buf[0] = ECU_SOCK_MSG_TYPE;
  buf[1] = position;
  memcpy(buf + 2, message, sizeof(ecu_message_t));
  memcpy(buf + 2 + sizeof(ecu_message_t), enclave_signature,
         sizeof(enclave_signature));
  if (send(sockfd, buf, msg_len, 0) == -1) {
    printf("error sending ecu message to real ecu\n");
    return CP_ERROR;
  }

  memset(ecu_signature, 0, sizeof(cp_ec256_signature_t));
  if (recv(sockfd, ecu_signature, sizeof(cp_ec256_signature_t), 0) == -1) {
    printf("error receiving ecu signature\n");
    return CP_ERROR;
  }
  return CP_SUCCESS;
}

commpact_status_t setupSocket() {
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    printf("error opening stream socket");
    exit(1);
  }

  sockaddr_in server;
  server.sin_family = AF_INET;

  inet_pton(AF_INET, SERVER_IP, &(server.sin_addr));
  server.sin_port = htons(PORT);

  if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
    printf("error connecting stream socket");
    exit(1);
  }

  return CP_SUCCESS;
}

commpact_status_t getRealECUPubKey(uint8_t position,
                                   cp_ec256_public_t *pub_key) {
  if (recv(sockfd, pub_key, sizeof(cp_ec256_public_t), 0)) {
    printf("error connecting stream socket");
    exit(1);
  }
  return CP_SUCCESS;
}
