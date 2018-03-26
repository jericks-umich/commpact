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

int main(int argc, char const *argv[]) {
    int fd;
    int res = -ENOSYS;
    struct Dot3WSMPSockAddr sockAddr;
    socklen_t addrLen = sizeof(sockAddr);

    uint8_t *pBuf = NULL;
    int bufLen = P1609_RX_BUF_SIZE;
    struct Dot3WSMPHdr *pHdr;

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
    pBuf = calloc(bufLen, sizeof(uint8_t));
    if (pBuf == NULL) {
        perror("Allocate buffer error: ");
        goto Error;
    }

    while (1) {
        // receive
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
        pBuf[res] = '\0';
        printf("Received %d bytes (, including %d bytes of header): %s\n", res, WSMP_HDR_SIZE, pBuf + WSMP_HDR_SIZE);
        for (int i = 0; i < res; ++i) {
            printf("%.2X ", pBuf[i] & 0xFF);
            if ((i + 1) == res || (i + 1) % 16 == 0)
                printf("\n");
        }
        // printf("\n");

        // echo
        // prepare header
        pHdr = (struct Dot3WSMPHdr *) pBuf;
        memcpy(pHdr->Tx.DA, pHdr->Rx.SA, WSM_HDR_MAC_LEN);
        pHdr->Tx.Priority   = P1609_CONFIG_DEF_PRIORITY;
        pHdr->Tx.ExpiryTime = WSM_HDR_DEFAULT_EXPIRY_TIME;
        // pHdr->Version       = DOT3_WSMP_VERSION_3;

        // send
        printf("echo\n\n");
        res = sendto(fd, pBuf, res, 0, NULL, 0);
        if (res < 0) {
            perror("Error: ");
            goto Error;
        }
    }

    if (res < 0)
        goto Error;

Error:
    close(fd);
    free(pBuf);
    return res;
}
