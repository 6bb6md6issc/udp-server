#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

int main() {

    int bpf_fd = open("/dev/bpf0", O_RDONLY);
    if (bpf_fd < 0) {
        perror("open");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "en0");

    if(ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
        perror("BIOCSETIF");
        close(bpf_fd);
        return 1;
    }

    struct bpf_insn filter[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12), 
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 9), // compare against ipv4
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 14), // x <- 14 skip ethernet II header
        BPF_STMT(BPF_LD+BPF_B+BPF_IND, 9), // ipv4 header + 9 index of protocol
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x11, 0, 6), // compare against udp
        BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14), // x <- ipv4 header length
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 16), // A <- dest port in udp header
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3039, 0, 3), // port ? == 12345
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0), // X <- len of packet
        BPF_STMT(BPF_MISC+BPF_TXA, 0), // A <- X
        BPF_STMT(BPF_RET+BPF_A, 0),
        BPF_STMT(BPF_RET+BPF_K, 0)
    };

    struct bpf_program program = {
        .bf_len = (u_int) (sizeof filter / sizeof filter[0]),
        .bf_insns = filter,
    };

    if (ioctl(bpf_fd, BIOCSETF, &program) == -1) {
        perror("BIOCSETF");
        close(bpf_fd);
        return 1;
    }
    u_int len;
    if (ioctl(bpf_fd, BIOCGBLEN, &len) < 0){
        perror("BIOCGBLEN");
        close(bpf_fd);
        return 1;
    }

    unsigned char * buffer = malloc(len);
    if (buffer == NULL) {
        perror("malloc");
        close(bpf_fd);
        return 1;
    }

    u_int enable = 1;
    if (ioctl(bpf_fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("BIOCIMMEDIATE");
        close(bpf_fd);
        return 1;
    }

    while (1) {
        ssize_t read_len = read(bpf_fd, buffer, len);
        if (read_len < 0) {
            perror("read");
            break;
        }
        struct bpf_hdr* hdr = (struct bpf_hdr*) (buffer);
        unsigned char* packet = buffer + hdr->bh_hdrlen;
        
        for (int i = 0; i < hdr->bh_caplen; i++) {
            printf("%02x ", (unsigned int) packet[i]);
            if ((i + 1) % 16 == 0){
                printf("\n");
            }
        }
        printf("\n");
    }
    free(buffer);
    close(bpf_fd);
    return 0;
}