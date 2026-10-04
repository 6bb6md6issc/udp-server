#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

int main(){
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res;

    int get_res = getaddrinfo(
        NULL, 
        "12345",
        &hints,
        &res
    );

    if (get_res != 0) {
        gai_strerror(get_res);
        return 1;
    }

    struct addrinfo* cur;
    int sockfd;
    for (cur = res; cur != NULL; cur = cur->ai_next) {
        sockfd = socket(
            cur->ai_family, 
            cur->ai_socktype, 
            cur->ai_protocol
        );
        if (sockfd < 0) {
            continue;
        }

        int bind_res = bind(
            sockfd, 
            (struct sockaddr*) cur->ai_addr, 
            (socklen_t) cur->ai_addrlen
        );

        if (bind_res < 0){
            close(sockfd);
            continue;
        }

        break;
    }

    if (cur == NULL) {
        close(sockfd);
        return 1;
    }

    char rbuf[1024];

    size_t packet_cnt = 0;
    size_t recvfrom_cnt = 0;
    size_t clock_cnt = 0;

    struct timespec start = {0};
    struct timespec end = {0};

    struct timeval timeout = {
        .tv_sec = 1,
        .tv_usec = 0
    };

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == -1) {
        perror("setsockopt");
        close(sockfd);
        return 1;
    }

    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof client_addr;

        ssize_t read_len = recvfrom(
            sockfd, 
            rbuf, 
            sizeof rbuf, 
            0, 
            (struct sockaddr*) &client_addr, 
            &addr_len
        );
        
        if (read_len < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (packet_cnt > 0) {
                    break;
                }
                continue;
            }
                
            perror("recvfrom");
            break;
        }
        if (packet_cnt == 0) {
            if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
                perror("clock_gettime");
                break;
            }
        }
        recvfrom_cnt++;
        packet_cnt++;
        clock_gettime(CLOCK_MONOTONIC, &end);
        clock_cnt++;
    }
    double elapsed = (double)(end.tv_sec - start.tv_sec) 
                  + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("packet count: %zu\n", packet_cnt);
    printf("recvfrom() count: %zu\n", recvfrom_cnt);
    printf("clock_gettime count: %zu\n", clock_cnt);
    printf("Elapsed: %.6f seconds\n", elapsed);

    close(sockfd);
    freeaddrinfo(res);

}


