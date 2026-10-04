#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/bpf.h>

#include <string.h>
#include <stdlib.h>

#include <inttypes.h>
#include <assert.h>

int main(){
  int bpf_fd = open("/dev/bpf0", O_RDONLY); 
  if (bpf_fd < 0) {
    perror("open");
    return 1;
  }
  printf("bpf file descriptor is: %d\n", bpf_fd);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof ifr);
  strcpy(ifr.ifr_name, "lo0"); // change to lo0, inside the machien
  
  if (ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
    perror("BIOCSETIF");
    close(bpf_fd);
    return 1;
  };
  
  u_int len;
  if (ioctl(bpf_fd, BIOCGBLEN, &len) < 0) {
    perror("BIOCGBLEN");
    close(bpf_fd);
    return 1;
  }
  printf("bpf buffer length: %d\n", len);

  int enable = 1;


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
  size_t syscall_cnt = 0;
  while (1) {
    ssize_t read_len = read(bpf_fd, buffer, len);
    syscall_cnt += 1;
    if (read_len == -1) {
      perror("read");
      break;
    }
    for (int i = 0; i < read_len; i += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen)) {
        hdr = (struct bpf_hdr*) buffer + i
        packet_count += 1;
    }
  }
  
  free(buffer);
  close(bpf_fd);
  return 0;
}