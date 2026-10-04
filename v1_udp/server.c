#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

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

    if (get_res < 0) {
        perror("getaddrinfo");
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

    

    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof client_addr;
        char rbuf[1024];

        ssize_t read_len = recvfrom(
            sockfd, 
            rbuf, 
            sizeof rbuf, 
            0, 
            (struct sockaddr*) &client_addr, 
            &addr_len
        );
        if (read_len < 0) {
            perror("recvfrom");
            break;
        }
        fwrite(rbuf, 1, (size_t) read_len, stdout);
        fflush(stdout);

    }

    close(sockfd);
    freeaddrinfo(res);

}


