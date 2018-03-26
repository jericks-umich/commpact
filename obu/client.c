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

int main(int argc, char const *argv[]) {
    int fd;
    int res = -ENOSYS;
    struct Dot3WSMPSockAddr sockAddr;
    socklen_t addrLen = sizeof(sockAddr);
    struct timespec t1, t2, t3, t4;
    int debug = 0;

    uint8_t *pBuf = NULL;
    int bufLen = 0;
    struct Dot3WSMPHdr *pHdr;

    int len = 64;
    if (argc > 1) {
        len = atoi(argv[1]);
    }
    if (argc >= 3) debug = 1;

    if (debug) printf("Data size: %d bytes\n", len);


    // open socket
    fd = socket(AF_IEEE1609_WSMP, SOCK_DGRAM, PROTO_IEEE1609DOT3_WSMP);
    if (fd < 0) {
        res = -errno;
        perror("Error: ");
        goto Error;
    }

    // set address
    sockAddr.Family = AF_IEEE1609_WSMP;
    memset(sockAddr.Hdr.Tx.DA, 0, sizeof(sockAddr.Hdr.Tx.DA));
    sockAddr.Hdr.Version       = DOT3_WSMP_VERSION_3;
    sockAddr.Hdr.Tx.Priority   = P1609_CONFIG_DEF_PRIORITY;
    sockAddr.Hdr.Tx.ExpiryTime = 0;
    sockAddr.Hdr.ChannelNumber = 178;
    sockAddr.Hdr.DataRate      = DOT3_WSMP_WSM_DATARATE_6MBPS;
    sockAddr.Hdr.TxPower       = 32;
    sockAddr.Hdr.PSID          = htonl(DOT3_WSMP_PSID_ALL); // Promiscuous receive
    sockAddr.Hdr.HdrExtFlags   = 0x07; // Channel | DataRate | TxPwr

    res = bind(fd, (struct sockaddr *)&sockAddr, sizeof(sockAddr));
    if (res < 0) {
        res = -errno;
        perror("Error: ");
        goto Error;
    }

    // allocate buffer
    pBuf = calloc(MAX_BUF_LEN, sizeof(uint8_t));
    if (pBuf == NULL) {
        perror("Allocate buffer error: ");
        goto Error;
    }

    // prepare header
    pHdr = (struct Dot3WSMPHdr *) pBuf;
    memset(pHdr->Tx.DA, WSM_HDR_MAC_TX_FILL, WSM_HDR_MAC_LEN);
    pHdr->Tx.Priority   = P1609_CONFIG_DEF_PRIORITY;
    pHdr->Tx.ExpiryTime = WSM_HDR_DEFAULT_EXPIRY_TIME;
    pHdr->Version       = DOT3_WSMP_VERSION_3;
    pHdr->ChannelNumber = 178;
    pHdr->DataRate      = DOT3_WSMP_WSM_DATARATE_6MBPS;
    pHdr->TxPower       = 32;
    pHdr->PSID          = htonl(BSM_OPTS_WSM_PSID_DEFAULT);
    pHdr->Length        = htons(len);
    pHdr->HdrExtFlags   = 0x07; // Channel | DataRate | TxPwr

    bufLen += WSMP_HDR_SIZE;

    // fill data
    memset(pBuf + WSMP_HDR_SIZE, '1', len);
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
    clock_gettime(CLOCK_REALTIME, &t1);
    res = sendto(fd, pBuf, bufLen, 0, NULL, 0);
    clock_gettime(CLOCK_REALTIME, &t2);
    if (res < 0) {
        perror("Error: ");
        goto Error;
    }

    if (res < 0)
        goto Error;

    // wait for response
    // TODO: add timeout
    while (1) {
        // receive
        clock_gettime(CLOCK_REALTIME, &t3);
        res = recvfrom(fd, pBuf, bufLen, 0, (struct sockaddr *)&sockAddr, &addrLen);
        if (res < 0) {
            perror("Error: ");
            res = -errno;
            goto Error;
        }

        // nothing
        if (res == 0)
            continue;

        // print
        clock_gettime(CLOCK_REALTIME, &t4);
        pBuf[res] = '\0';
        if (debug) {
            printf("Received %d bytes (, including %d bytes of header): %s\n", res, WSMP_HDR_SIZE, pBuf + WSMP_HDR_SIZE);
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
    printf("%lld.%.9ld %lld.%.9ld",
        (long long)(t3.tv_sec - t3.tv_sec), t2.tv_nsec - t1.tv_nsec,
        (long long)(t4.tv_sec - t1.tv_sec), t4.tv_nsec - t1.tv_nsec);

    goto Success;

Error:
    close(fd);
    free(pBuf);
Success:
    return res;
}
