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
  strcpy(ifr.ifr_name, "en0"); // change to lo0, inside the machien
  
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


  if (ioctl(bpf_fd, BIOCIMMEDIATE, &enable) < 0) {
    perror("BIOCIMMEDIATE");
    close(bpf_fd);
    return 1;
  }

  unsigned char* buffer = malloc(len);

  struct bpf_hdr* hdr;

  while (1) {
    ssize_t read_len = read(bpf_fd, buffer, len);
    if (read_len == -1) {
      close(bpf_fd);
      perror("read");
      break;
    }

    for (int i = 0; i < read_len; i += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen)) {
      
      hdr = (struct bpf_hdr*) (buffer + i);
      int ether_header = i + hdr->bh_hdrlen;

      uint16_t ether_type = (uint16_t) buffer[ether_header + 12] << 8 | buffer[ether_header + 13];
      if (ether_type != 0x0800) {
        // not IPv4
        continue;
      }
      size_t ipv4_idx = i + hdr->bh_hdrlen + 14;

      if ((buffer[ipv4_idx] >> 4) != 4){
        // ethernet and ip header mis-aligned
        continue;
      }

      if (buffer[ipv4_idx + 9] != 0x11) {
        // not udp
        continue;
      }

      uint8_t ihl = buffer[ipv4_idx] & 0b00001111;
      size_t udp_idx = ipv4_idx + ihl * 4;
      uint16_t dest_port = (buffer[udp_idx + 2] << 8) | buffer[udp_idx + 3];
      if (dest_port != 12345) {
        // not port 12345
        continue;
      }

      unsigned char* packet = buffer + i + hdr->bh_hdrlen;
      for (size_t idx = 0; idx < hdr->bh_caplen; idx++) {
        printf("%02x ", packet[idx]);
        if ((idx + 1) % 16 == 0) {
          printf("\n");
        }
      }

      printf("\n");
    }
  }
  
  free(buffer);
  close(bpf_fd);
  return 0;
}