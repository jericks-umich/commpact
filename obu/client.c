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


double timespec_subtract(struct timespec *x, struct timespec *y) {
    double t1 = x->tv_sec + x->tv_nsec / 1000000000.0;
    double t2 = y->tv_sec + y->tv_nsec / 1000000000.0;

    return t1 - t2;
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
    uint8_t *pData = NULL;
    int bufLen = 0;

    // measurement
    struct timespec t1, t2, t3, t4, ts;
    double result;

    // parameters
    // seq number
    int seq = 1;
    // packet length
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
    if (argc > 1) seq = atoi(argv[1]);
    if (argc > 2) len = atoi(argv[2]);
    if (argc > 3) channelNumber = atoi(argv[3]);
    if (argc > 4) dataRate = atoi(argv[4]);
    if (argc > 5) txPower = atoi(argv[5]);
    if (argc > 6) debug = 1;

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

    // timeout
    struct timeval timeout; // 10 ms
    timeout.tv_sec = 0;
    timeout.tv_usec = 20 * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed: ");
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

    // send
    pData = pBuf + WSMP_HDR_SIZE;
    // put seq #
    memcpy(pData, &seq, sizeof(seq));
    pData += sizeof(seq);
    // put timestamp
    clock_gettime(CLOCK_REALTIME, &t1);
    memcpy(pData, &t1, sizeof(t1));

    if (debug) {
        printf("Send %d bytes: %s\n", bufLen, pBuf + WSMP_HDR_SIZE);
        for (int i = 0; i < bufLen; ++i) {
            printf("%.2X ", pBuf[i] & 0xFF);
            if ((i + 1) == bufLen || (i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }

    res = sendto(fd, pBuf, bufLen, 0, NULL, 0);
    clock_gettime(CLOCK_REALTIME, &t2);
    if (res < 0) {
        res = -errno;
        perror("sendto failed: ");
        goto Error;
    }

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
                // perror("timeout: ");
                printf("-1\n");
                // fprintf(stderr, "packet loss\n");
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
        memcpy(&ts, pData, sizeof(ts));
        if (debug) {
            printf("t1: %lld.%.9ld, ts: %lld.%.9ld\n", (long long)t1.tv_sec, t1.tv_nsec,
                                                       (long long)ts.tv_sec, ts.tv_nsec);
        }
        // timestamp, not match
        if (t1.tv_sec != ts.tv_sec ||
            t1.tv_nsec != ts.tv_nsec)
            continue;

        // print
        if (debug) {
            pBuf[res] = '\0';
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
    result = timespec_subtract(&t4, &t1);
    // printf("%lld.%.9ld\n", (long long)result.tv_sec, result.tv_nsec);
    printf("%lf\n", result);

Error:
    if (debug) {
        printf("resource cleanup\n");
    }
    close(fd);
    free(pBuf);

    return res;
}
