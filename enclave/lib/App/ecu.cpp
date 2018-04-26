#include "ecu.h"
#include "commpact.h"
#include "initialsetup.h"

#include "sgx_tcrypto.h"

#include <stdlib.h>

//#define TIME_SIGN_VERIFY

///////////////////////
// GLOBAL PARAMETERS //
///////////////////////
int sockfd;
sockaddr_in addr;
unsigned int addr_len;
// ecu_message_t ecu_parameters;
// cp_ec256_public_t enclave_pub_key;
// cp_ec256_private_t ecu_priv_key;
// cp_ec256_public_t ecu_pub_key;

// map index is platoon position
// std::unordered_map<uint64_t, ecu_t> ecus;
ecu_t ecus[COMMPACT_MAX_ENCLAVES];

#ifdef TIME_SIGN_VERIFY
FILE *latencyfd;

uint32_t start_time() {
  volatile uint32_t time;
  asm __volatile__("  mfence       \n"
                   "  lfence       \n"
                   "  rdtsc        \n"
                   "  lfence       \n"
                   : "=a"(time));
  return time;
}
uint32_t end_time() {
  volatile uint32_t time;
  asm __volatile__("  lfence       \n"
                   "  rdtsc        \n"
                   : "=a"(time));
  return time;
}

#endif

commpact_status_t setGetEnclavePubKey(uint8_t position,
                                      cp_ec256_public_t *enclave_pub_key,
                                      cp_ec256_public_t *ecu_pub_key) {
  // set enclave's pubkey in ecu
  ecu_t *ecu = &ecus[position];
  memcpy(&(ecu->enclave_pub_key), enclave_pub_key, sizeof(cp_ec256_public_t));

  // generate ecu keys and set ecu's pubkey in enclave
  generateKeyPair(position, ecu_pub_key);

  return CP_SUCCESS;
}

commpact_status_t setGetEnclavePubKeyRealECU(uint8_t position,
                                             cp_ec256_public_t *enclave_pub_key,
                                             cp_ec256_public_t *ecu_pub_key) {
  // clang-format off
  // msg type | position | public_key
  // one byte | one byte | sizeof(cp_ec256_public_t)
  // clang-format on
  uint64_t msg_len = 2 + +sizeof(cp_ec256_public_t);
  uint8_t buf[msg_len];
  int nbytes;
  memset(buf, 0, msg_len);
  buf[0] = ECU_SOCK_PUB_KEY_TYPE;
  buf[1] = position;
  memcpy(buf + 2, enclave_pub_key, sizeof(cp_ec256_public_t));
  // printf("sending 2 bytes + pubkey: ");
  // for (int i = 0; i < msg_len; i++) {
  //  printf("%02x", buf[i]);
  //}
  // printf("\n");
  nbytes = sendto(sockfd, buf, msg_len, 0, (struct sockaddr *)&addr, addr_len);
  if (nbytes < (2 + sizeof(cp_ec256_public_t))) {
    printf("error sending ecu pubkey to real ecu\n");
    return CP_ERROR;
  }

  nbytes = recvfrom(sockfd, ecu_pub_key, sizeof(cp_ec256_public_t), 0,
                    (struct sockaddr *)&addr, &addr_len);
  if (nbytes < sizeof(cp_ec256_public_t)) {
    printf("error receiving pubkey from udp socket");
    return CP_ERROR;
  }
  // printf("received pubkey: ");
  // for (int i = 0; i < sizeof(cp_ec256_public_t); i++) {
  //  printf("%02x", ((uint8_t *)ecu_pub_key)[i]);
  //}
  // printf("\n");

  return CP_SUCCESS;
}

commpact_status_t setParametersECU(uint8_t position,
                                   cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature) {

  uint8_t verify_result = 0;
  void *handle;
  ecu_t *ecu = &ecus[position];
#ifdef TIME_SIGN_VERIFY
  uint32_t start, end, diff;
  double compute_time;
  start = start_time();
#endif
  sgx_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t),
                   (sgx_ec256_public_t *)&(ecu->enclave_pub_key),
                   (sgx_ec256_signature_t *)enclave_signature, &verify_result,
                   handle);

  if (verify_result != CP_EC_VALID) {
    memset(ecu_signature, 0, sizeof(cp_ec256_signature_t));
    return CP_SUCCESS;
  }
#ifdef TIME_SIGN_VERIFY
  end = end_time();
  if (end < start) {
    diff = end + (1 << 31) - start + (1 << 31);
    compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  } else {
    diff = end - start;
    compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  }
  fprintf(latencyfd, "verify cycles: %u | ", diff);
  fprintf(latencyfd, "verify: %f | ", compute_time);
  fflush(latencyfd);
#endif

  memcpy(&(ecu->ecu_parameters), message, sizeof(ecu_message_t));

// Sign the message
#ifdef TIME_SIGN_VERIFY
  start = start_time();
#endif
  signMessage(ecu, message, ecu_signature);
#ifdef TIME_SIGN_VERIFY
  end = end_time();
  if (end < start) {
    diff = end + (1 << 31) - start + (1 << 31);
    compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  } else {
    diff = end - start;
    compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  }
  fprintf(latencyfd, "sign cycles: %u | ", diff);
  fprintf(latencyfd, "sign: %8f\n", compute_time);
  fflush(latencyfd);
#endif

  return CP_SUCCESS;
}

commpact_status_t generateKeyPair(uint8_t position,
                                  cp_ec256_public_t *pub_key) {

  int retval = 0;
  sgx_status_t status = SGX_SUCCESS;
  void *ecc_handle;
  ecu_t *ecu = &ecus[position];

#ifdef TIME_SIGN_VERIFY
  latencyfd = fopen(DEBUG_ECU_LATENCY_FILENAME, "w");
  if (latencyfd == NULL) {
    printf("error: can't open latency file\n");
    exit(1);
  }
#endif

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

void copyECUMessage(void *dest, ecu_message_t *src) {
#ifdef USING_BIG_ENDIAN
  uint64_t temp;
  temp = htond(src->recovery_phase_timeout);
  memcpy(dest, &temp, sizeof(double));
  temp = htond(src->upper_speed);
  memcpy(dest + sizeof(double) * 1, &temp, sizeof(double));
  temp = htond(src->lower_speed);
  memcpy(dest + sizeof(double) * 2, &temp, sizeof(double));
  temp = htond(src->upper_accel);
  memcpy(dest + sizeof(double) * 3, &temp, sizeof(double));
  temp = htond(src->lower_accel);
  memcpy(dest + sizeof(double) * 4, &temp, sizeof(double));
  temp = htond(src->max_decel);
  memcpy(dest + sizeof(double) * 5, &temp, sizeof(double));
  // grab last 2 uint8_t's
  memcpy(dest + sizeof(double) * 6, src + sizeof(double) * 6,
         sizeof(uint8_t) * 2);
#else
  memcpy(dest, src, sizeof(ecu_message_t));
#endif
}

void copySignature(void *dest, cp_ec256_signature_t *src) {
#ifdef USING_BIG_ENDIAN
  uint32_t temp;
  for (int i = 0; i < CP_NISTP_ECP256_KEY_SIZE; i++) {
    temp = htonl(src->x[i]);
    memcpy(dest + sizeof(uint32_t) * i, &temp, sizeof(uint32_t));
  }
  for (int i = 0; i < CP_NISTP_ECP256_KEY_SIZE; i++) {
    temp = htonl(src->y[i]);
    memcpy(dest + sizeof(uint32_t) * i, &temp, sizeof(uint32_t));
  }
#else
  memcpy(dest, src, sizeof(cp_ec256_signature_t));
#endif
}

commpact_status_t setParametersRealECU(uint8_t position,
                                       cp_ec256_signature_t *enclave_signature,
                                       ecu_message_t *message,
                                       cp_ec256_signature_t *ecu_signature) {
  uint64_t msg_len = 2 + sizeof(ecu_message_t) + sizeof(cp_ec256_signature_t);
  uint8_t buf[msg_len];
  int nbytes;
  memset(buf, 0, msg_len);
  // clang-format off
          // MSG should look like: msg_type | vehicle position | message               |enclave_signature
          //                       1 byte   | byte             | sizeof(ecu_message_t) |sizeof(cp_ec256_signature_t)
  // clang-format on
  buf[0] = ECU_SOCK_MSG_TYPE;
  buf[1] = position;
  copyECUMessage(buf + 2, message);
  // memcpy(buf + 2, message, sizeof(ecu_message_t));
  copySignature(buf + 2 + sizeof(ecu_message_t), enclave_signature);
  // memcpy(buf + 2 + sizeof(ecu_message_t), enclave_signature,
  //       sizeof(cp_ec256_signature_t));
  // printf("sending enclave message: ");
  // for (int i = 0; i < sizeof(ecu_message_t); i++) {
  //  printf("%02x", ((uint8_t *)buf + 2)[i]);
  //}
  // printf("\n");
  // printf("sending enclave signature: ");
  // for (int i = 0; i < sizeof(cp_ec256_signature_t); i++) {
  //  printf("%02x", ((uint8_t *)buf + 2 + sizeof(ecu_message_t))[i]);
  //}
  // printf("\n");
  // printf("sending packet: ");
  // for (int i = 0; i < msg_len; i++) {
  //  printf("%02x", buf[i]);
  //}
  // printf("\n");
  nbytes = sendto(sockfd, buf, msg_len, 0, (struct sockaddr *)&addr, addr_len);
  if (nbytes < (2 + sizeof(ecu_message_t) + sizeof(cp_ec256_signature_t))) {
    printf("error sending ecu message to real ecu\n");
    return CP_ERROR;
  }

  cp_ec256_signature_t temp_sig;
  memset(&temp_sig, 0, sizeof(cp_ec256_signature_t));
  memset(ecu_signature, 0, sizeof(cp_ec256_signature_t));
  nbytes = recvfrom(sockfd, &temp_sig, sizeof(cp_ec256_signature_t), 0,
                    (struct sockaddr *)&addr, &addr_len);
  if (nbytes < sizeof(cp_ec256_signature_t)) {
    printf("error receiving ecu signature\n");
    return CP_ERROR;
  }
  copySignature(ecu_signature, &temp_sig);
  //  printf("received signature: ");
  //  for (int i = 0; i < sizeof(cp_ec256_signature_t); i++) {
  //    printf("%02x", ((uint8_t *)ecu_signature)[i]);
  //  }
  //  printf("\n");
  return CP_SUCCESS;
}

commpact_status_t setupSocket() {
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    printf("error opening udp socket");
    exit(1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, SERVER_IP, &(addr.sin_addr));
  addr.sin_port = htons(PORT);
  addr_len = sizeof(addr);

  // if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
  //  printf("error connecting udp socket");
  //  exit(1);
  //}

  return CP_SUCCESS;
}
