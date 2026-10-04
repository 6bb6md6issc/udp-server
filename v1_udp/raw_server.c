#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>

int main() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof addr) == -1) {
        perror("bind");
        close(sockfd);
        return 1;
    }
    while (1) {
        char rbuf[1024];
        fprintf(stderr, "before read\n");
        int read_len = read(sockfd, rbuf, sizeof rbuf);
        if (read_len == -1) {
            perror("read");
            break;
        }
        
        fprintf(stderr, "after read: %zd bytes\n", read_len);
        if (read_len < 20) {
            fprintf(stderr, "packet too short\n");
            continue;
        }
        size_t header_len = (rbuf[0] & 0x0F) * 4;
        fprintf(
            stderr, 
            "IP header length=%zu, protocol=%u\n", 
            header_len, 
            (unsigned char)rbuf[9]
        );
        if (
            read_len < header_len + 8 || 
            header_len < 20 || 
            rbuf[9] != IPPROTO_UDP
        ) {
            continue;
        }
        fwrite(
            rbuf + header_len + 8, 
            1, 
            (size_t) read_len - header_len - 8, 
            stdout
        );
        fflush(stdout);

    }
    close(sockfd);
}