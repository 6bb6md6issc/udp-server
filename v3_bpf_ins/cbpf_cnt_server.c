#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/bpf.h>

#include <string.h>
#include <stdlib.h>

#include <inttypes.h>
#include <assert.h>
#include <time.h>

int main(){
  int bpf_fd = open("/dev/bpf0", O_RDONLY); 
  if (bpf_fd < 0) {
    perror("open");
    return 1;
  }
  printf("bpf file descriptor is: %d\n", bpf_fd);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof ifr);
  strcpy(ifr.ifr_name, "en0");
  
  if (ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
    perror("BIOCSETIF");
    close(bpf_fd);
    return 1;
  };

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

  struct timeval timeout = {
    .tv_sec = 1,
    .tv_usec = 0
  };
  if (ioctl(bpf_fd, BIOCSRTIMEOUT, &timeout) == -1) {
    perror("BIOCSRTIMEOUT");
    close(bpf_fd);
    return 1;
  }

  u_int len;
  if (ioctl(bpf_fd, BIOCGBLEN, &len) < 0) {
    perror("BIOCGBLEN");
    close(bpf_fd);
    return 1;
  }

  // int enable = 1;


//   if (ioctl(bpf_fd, BIOCIMMEDIATE, &enable) < 0) {
//     perror("BIOCIMMEDIATE");
//     close(bpf_fd);
//     return 1;
//   }

  unsigned char* buffer = malloc(len);
  if (buffer == NULL) {
    close(bpf_fd);
    return 1;
  }

  struct bpf_hdr* hdr;
  size_t packet_count = 0;
  size_t read_call_cnt = 0;
  size_t clock_call_cnt = 0;
  size_t batch_num = 0;
  struct timespec start = {0};
  struct timespec end = {0};
  int started = 0;

  while (1) {
    ssize_t read_len = read(bpf_fd, buffer, len);
    read_call_cnt += 1;
    // fprintf(stderr, "read_len=%zd, started=%d\n", read_len, started);
    if (read_len == -1) {
      perror("read");
      break;
    }
    if (read_len == 0) {
      if (started)
        break;     // No packets returned; finish measurement.
      continue;      // Still waiting for the test to begin.
    }
    if (!started) {
      if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          perror("clock_gettime");
          break;
        }
        end = start;  // Struct assignment is valid C.
        started = 1;
    }
    for (int i = 0; i < read_len; i += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen)) {
        hdr = (struct bpf_hdr*) (buffer + i);
        packet_count += 1;
    }
    // if (++batch_num % 10 == 0) {
      clock_gettime(CLOCK_MONOTONIC, &end);
      clock_call_cnt++;
    // }
  }
  double elapsed = (double)(end.tv_sec - start.tv_sec) 
                  + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
  printf("Elapsed: %.6f seconds\n", elapsed);
  printf("read system call: %zu\n", read_call_cnt);
  printf("clock system call: %zu\n", clock_call_cnt);
  printf("packet count: %zu\n", packet_count);
  
  free(buffer);
  close(bpf_fd);
  return 0;
}