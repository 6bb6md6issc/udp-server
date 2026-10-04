#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main() {
    char w_buf[100] = "The fast brown fox jumps over a lazy dog to eat some good fruit";
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(12345);
    int result = inet_pton(AF_INET, "172.20.10.3", &sockaddr.sin_addr);
    if (result != 1) {
        perror("inet_pton");
        close(fd);
        return 1;
    }


    if (connect(fd, (struct sockaddr*) &sockaddr, sizeof (struct sockaddr_in)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    size_t success_cnt = 0;

    for (int i = 0; i < 100000; i++) {
        if (send(fd, w_buf, 64, 0) < 0) {
            perror("send");
            fprintf(stderr, "Successful sends before failure: %zu\n", success_cnt);
            close(fd);
            return 1;
        }
        success_cnt++;
    }
    printf("success send count: %zu\n", success_cnt);
    close(fd);
    return 0;
}