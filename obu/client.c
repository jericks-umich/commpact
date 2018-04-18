#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <time.h>

#include "dot3-wsmp.h"

#define MAX_BUF_LEN 4096
#define BSM_OPTS_WSM_PSID_DEFAULT   (0x10)
#define P1609_CONFIG_DEF_PRIORITY  2
#define P1609_RX_BUF_SIZE 4096
/// MAC address length in uint8_t
#define WSM_HDR_MAC_LEN 6

/// MAC address defined to 0xFFFFFFFFFFFF in Tx
#define WSM_HDR_MAC_TX_FILL  0xFF

/// WSM header expiry time=0, never expire
#define WSM_HDR_DEFAULT_EXPIRY_TIME 0


int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int nsec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
    y->tv_nsec -= 1000000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_nsec - y->tv_nsec > 1000000000) {
    int nsec = (x->tv_nsec - y->tv_nsec) / 1000000000;
    y->tv_nsec += 1000000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_nsec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_nsec = x->tv_nsec - y->tv_nsec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

int init_socket(int channelNumber, int dataRate, int txPower) {
    int fd;
    int res;
    struct Dot3WSMPSockAddr sockAddr;

    // open socket
    fd = socket(AF_IEEE1609_WSMP, SOCK_DGRAM, PROTO_IEEE1609DOT3_WSMP);
    if (fd < 0) {
        perror("socket failed: ");
        return fd;
    }

    // set address
    sockAddr.Family = AF_IEEE1609_WSMP;
    memset(sockAddr.Hdr.Tx.DA, 0, sizeof(sockAddr.Hdr.Tx.DA));
    sockAddr.Hdr.Version       = DOT3_WSMP_VERSION_3;
    sockAddr.Hdr.Tx.Priority   = P1609_CONFIG_DEF_PRIORITY;
    sockAddr.Hdr.Tx.ExpiryTime = 0;
    sockAddr.Hdr.ChannelNumber = channelNumber;
    sockAddr.Hdr.DataRate      = dataRate;
    sockAddr.Hdr.TxPower       = txPower;
    sockAddr.Hdr.PSID          = htonl(DOT3_WSMP_PSID_ALL); // Promiscuous receive
    sockAddr.Hdr.HdrExtFlags   = 0x07; // Channel | DataRate | TxPwr

    res = bind(fd, (struct sockaddr *)&sockAddr, sizeof(sockAddr));
    if (res < 0) {
        perror("bind failed: ");
        close(fd);
        return res;
    }

    // success
    return fd;
}

int main(int argc, char const *argv[]) {
    // socket
    int fd;
    int res = -ENOSYS;
    struct Dot3WSMPSockAddr sockAddr;
    socklen_t addrLen = sizeof(sockAddr);

    // data
    struct Dot3WSMPHdr *pHdr;
    uint8_t *pBuf = NULL;
    int bufLen = 0;
    time_t ts1, ts2;

    // measurement
    struct timespec t1, t2, t3, t4, result1, result2;

    // parameters
    // <len> <debug>
    int len = 64;
    // 172, 174, 175, 176, 178 (CCH), 180, 181, 182, 184
    int channelNumber = 178;
    // "dot3-wsmp.h"
    // 3, 4 (???: why invalid)
    // 6, 9, 12, 18, 24, 27, 36, 48, 54
    // 72, 96, 108 (for channel 175 & 181)
    int dataRate = DOT3_WSMP_WSM_DATARATE_6MBPS;
    // "dot3-wsmp.h"
    // [-64, 64] dBm
    int txPower = 32;
    int debug = 0;
    if (argc > 1) len = atoi(argv[1]);
    if (argc > 2) channelNumber = atoi(argv[2]);
    if (argc > 3) dataRate = atoi(argv[3]);
    if (argc > 4) txPower = atoi(argv[4]);
    if (argc > 5) debug = 1;

    if (debug) {
        printf("Packet size: %d bytes\n", len);
        printf("Channel: %d\n", channelNumber);
        printf("Data rate: %d\n", dataRate);
        printf("Tx power: %d\n", txPower);
    }

    srand(time(NULL));

    // open socket
    fd = init_socket(channelNumber, dataRate, txPower);
    if (fd < 0) {
        res = -errno;
        goto Error;
    }

    // allocate buffer
    pBuf = calloc(MAX_BUF_LEN, sizeof(uint8_t));
    if (pBuf == NULL) {
        perror("calloc failed: ");
        goto Error;
    }

    // prepare header
    pHdr = (struct Dot3WSMPHdr *) pBuf;
    memset(pHdr->Tx.DA, WSM_HDR_MAC_TX_FILL, WSM_HDR_MAC_LEN);
    pHdr->Tx.Priority   = P1609_CONFIG_DEF_PRIORITY;
    pHdr->Tx.ExpiryTime = WSM_HDR_DEFAULT_EXPIRY_TIME;
    pHdr->Version       = DOT3_WSMP_VERSION_3;
    pHdr->ChannelNumber = channelNumber;
    pHdr->DataRate      = dataRate;
    pHdr->TxPower       = txPower;
    pHdr->PSID          = htonl(BSM_OPTS_WSM_PSID_DEFAULT);
    pHdr->Length        = htons(len);
    pHdr->HdrExtFlags   = 0x07; // Channel | DataRate | TxPwr

    bufLen += WSMP_HDR_SIZE;

    // fill data
    memset(pBuf + WSMP_HDR_SIZE, 0, len);
    bufLen += len;
    pBuf[bufLen - 1] = '\0';
    if (debug) {
        printf("Send %d bytes: %s\n", bufLen, pBuf + WSMP_HDR_SIZE);
        for (int i = 0; i < bufLen; ++i) {
            printf("%.2X ", pBuf[i] & 0xFF);
            if ((i + 1) == bufLen || (i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }

    // send
    ts1 = time(NULL);
    memcpy(pBuf + WSMP_HDR_SIZE, &ts1, sizeof(ts1));
    clock_gettime(CLOCK_REALTIME, &t1);
    res = sendto(fd, pBuf, bufLen, 0, NULL, 0);
    clock_gettime(CLOCK_REALTIME, &t2);
    if (res < 0) {
        res = -errno;
        perror("sendto failed: ");
        goto Error;
    }

    // timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        perror("setsockopt failed");

    // wait for response
    while (1) {
        // receive
        clock_gettime(CLOCK_REALTIME, &t3);
        res = recvfrom(fd, pBuf, bufLen, 0, (struct sockaddr *)&sockAddr, &addrLen);
        clock_gettime(CLOCK_REALTIME, &t4);

        if (res < 0) {
            if (debug) {
                printf("res: %d, errno: %d (%s)\n", res, errno, strerror(errno));
            }

            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // timeout
                perror("timeout: ");
            } else {
                perror("recvfrom failed: ");
            }

            res = -errno;
            goto Error;
        }

        // nothing
        if (res == 0)
            continue;

        // check timestamp
        memcpy(&ts2, pBuf + WSMP_HDR_SIZE, sizeof(ts2));
        if (debug) {
            printf("ts1: %ld, ts2: %ld\n", ts1, ts2);
        }
        // timestamp, not match
        if (ts1 != ts2)
            continue;

        // print
        pBuf[res] = '\0';
        if (debug) {
            printf("Received %d bytes (, including %d bytes of header):\n", res, WSMP_HDR_SIZE);
            for (int i = 0; i < res; ++i) {
                printf("%.2X ", pBuf[i] & 0xFF);
                if ((i + 1) == res || (i + 1) % 16 == 0)
                    printf("\n");
            }
            printf("\n");
        }
        break;
    }

    // calculate time
    if (debug) {
        printf("Before sending: %lld.%.9ld\n", (long long)t1.tv_sec, t1.tv_nsec);
        printf("After sending: %lld.%.9ld\n", (long long)t2.tv_sec, t2.tv_nsec);
        printf("Before recving: %lld.%.9ld\n", (long long)t3.tv_sec, t3.tv_nsec);
        printf("After recving: %lld.%.9ld\n", (long long)t4.tv_sec, t4.tv_nsec);
    }
    timespec_subtract(&result1, &t4, &t1);
    timespec_subtract(&result2, &t4, &t2);
    printf("%lld.%.9ld %lld.%.9ld\n", (long long)result1.tv_sec, result1.tv_nsec,
                                      (long long)result2.tv_sec, result2.tv_nsec);

Error:
    if (debug) {
        printf("resource cleanup\n");
    }
    close(fd);
    free(pBuf);

    return res;
}
