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

#define BSM_OPTS_WSM_PSID_DEFAULT   (0x10)
#define P1609_CONFIG_DEF_PRIORITY  2
#define P1609_RX_BUF_SIZE 4096
/// MAC address length in uint8_t
#define WSM_HDR_MAC_LEN 6

/// MAC address defined to 0xFFFFFFFFFFFF in Tx
#define WSM_HDR_MAC_TX_FILL  0xFF

/// WSM header expiry time=0, never expire
#define WSM_HDR_DEFAULT_EXPIRY_TIME 0

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
    int fd;
    int res = -ENOSYS;
    struct Dot3WSMPSockAddr sockAddr;
    socklen_t addrLen = sizeof(sockAddr);
    struct timespec t1;

    uint8_t *pBuf = NULL;
    int bufLen = P1609_RX_BUF_SIZE;
    struct Dot3WSMPHdr *pHdr;

    // 172, 174, 175, 176, 178 (CCH), 180, 181, 182, 184
    int channelNumber = 178;
    // "dot3-wsmp.h"
    // 3, 4, 6, 9, 12, 18, 24, 27, 36, 48, 54, 72, 96, 108
    int dataRate = DOT3_WSMP_WSM_DATARATE_6MBPS;
    // "dot3-wsmp.h"
    // [-64, 64] dBm
    int txPower = 32;
    int debug = 0;
    if (argc > 1) channelNumber = atoi(argv[1]);
    if (argc > 2) dataRate = atoi(argv[2]);
    if (argc > 3) txPower = atoi(argv[3]);
    if (argc > 4) debug = atoi(argv[4]);

    if (debug) {
        printf("Channel: %d\n", channelNumber);
        printf("Data rate: %d\n", dataRate);
        printf("Tx power: %d\n", txPower);
    }

    // open socket
    fd = init_socket(channelNumber, dataRate, txPower);
    if (fd < 0) {
        res = -errno;
        goto Error;
    }

    // allocate buffer
    pBuf = calloc(bufLen, sizeof(uint8_t));
    if (pBuf == NULL) {
        perror("calloc failed: ");
        goto Error;
    }

    while (1) {
        // receive
        res = recvfrom(fd, pBuf, bufLen, 0, (struct sockaddr *)&sockAddr, &addrLen);
        if (res < 0) {
            perror("recvfrom failed: ");
            res = -errno;
            goto Error;
        }

        // nothing
        if (res == 0)
            continue;

        // print
        pBuf[res] = '\0';
        if (debug >= 2) {
            printf("Received %d bytes (, including %d bytes of header):\n", res, WSMP_HDR_SIZE);
            for (int i = 0; i < res; ++i) {
                printf("%.2X ", pBuf[i] & 0xFF);
                if ((i + 1) == res || (i + 1) % 16 == 0)
                    printf("\n");
            }
        }

        // echo back
        // prepare header
        pHdr = (struct Dot3WSMPHdr *) pBuf;
        memcpy(pHdr->Tx.DA, pHdr->Rx.SA, WSM_HDR_MAC_LEN);
        pHdr->Tx.Priority   = P1609_CONFIG_DEF_PRIORITY;
        pHdr->Tx.ExpiryTime = WSM_HDR_DEFAULT_EXPIRY_TIME;
        pHdr->Version       = DOT3_WSMP_VERSION_3;

        // send
        printf("echo\n");
        res = sendto(fd, pBuf, res, 0, NULL, 0);
        if (res < 0) {
            perror("sendto failed: ");
            goto Error;
        }

        if (debug >= 1) {
            clock_gettime(CLOCK_REALTIME, &t1);
            printf("ts: %lld.%.9ld\n", (long long)t1.tv_sec, t1.tv_nsec);
        }

        printf("==========\n");
    }

    if (res < 0)
        goto Error;

Error:
    close(fd);
    free(pBuf);
    return res;
}
