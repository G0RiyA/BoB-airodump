#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>

#include <sys/ioctl.h>

#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <pcap.h>

#include "airodump.hpp"

size_t height;

int main(int argc, const char* argv[]) {
  const char *interface;
  const u_int8_t *packet;
  struct pcap_pkthdr *header;
  char errbuf[PCAP_ERRBUF_SIZE];
  int i;
  int res;
  int ltime;
  pcap_t *pcap;
  const ratio_header_t *ratio_header;
  const frame_t *frame;
  struct winsize w;
  char *cmd;
  size_t interface_len;
  int channel;

  if (argc != 2) {
    printf("Usage:\n"
           "%s <interface>"
        , *argv);
    return 0;
  }
  
  interface = argv[1];
  interface_len = strlen(interface);
  cmd = (char*)malloc(interface_len + 0x40);
  
  if (!(pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf))) {
    dprintf(2, "Could not open the interface %s!\n%s\n", interface, errbuf);
    return 1;
  }

  printf("\e[?25l");
  ioctl(1, TIOCGWINSZ, &w);

  height = w.ws_row - 3;

  for(i = 1; i < w.ws_row; ++i) puts("");

  printf("\e[1;1H\e[2J");
  printf("\033[0d\033[0G");

  ltime = time(NULL);
  while(1) {
    res = pcap_next_ex(pcap, &header, &packet);
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
      dprintf(2, "Could not read a packet!\n");
      return 2;
    }

    ratio_header = (ratio_header_t*)packet;
    frame = (const frame_t*)(packet + ratio_header->length);
    // printf("signal: %hhd\ntype: %hhx", ratio_header->signal, frame->subtype);
    // getchar();
    /*
    switch (frame->subtype) {
    case 4: // probe request
      break;
    case 8: // beacon frame
      append_beacon_frame((beacon_t*)&frame[1], ratio_header->signal, (void*)(packet + header->caplen));
      break;
    }*/
    if(frame->subtype == 8 && frame->type == 0)
      append_beacon_frame((beacon_t*)&frame[1], ratio_header->signal, (void*)(packet + header->caplen));

    if (ltime + 6 <= time(NULL)) {
      std::sort(APs.begin(), APs.end(), AP_pointer_cmp);
      ltime = time(NULL);
    }

    print_ap(channel);

    channel = (channel + 1) % 14 + 1;
    sprintf(cmd, "sudo iwconfig '%s' channel '%d'", interface, channel);
    if (system(cmd)) {
      dprintf(2, "Could not change channel!\n%s\n", cmd);
      return 3;
    }
  }
}

void mac_to_str(u_int8_t *mac, char *buf) {
  sprintf(buf, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void append_beacon_frame(beacon_t *beacon, int8_t pwr, void* end) {
  // char mac_buf[18];
  ap_t *ap;
  tagged_parameter_t *cur;
  u_int16_t cipher_suite_count, pairwise_suite_count, auth_suite_count;
  int i;
  // mac_to_str(beacon->bss_id, mac_buf);
  // puts(mac_buf);
  // getchar();

  if (!(ap = AP_map[MAC2INT(beacon->bss_id)])) {
    ap = new AP();

    ap->ESSID = NULL;
    AP_map[MAC2INT(beacon->bss_id)] = ap;
    memcpy(ap->bssid, beacon->bss_id, 6);
    ap->enc = 0;
    ap->cipher = 0;
    ap->auth = 0;

    cur = beacon->tp;
    while (cur < end) {
      if(cur->number == 0) {
        ap->ESSID = new std::string((char*)cur->data, cur->length);
      }
      else if (cur->number == 48) {
        ap->enc = 3;
        ap->cipher = 0;
        ap->auth = 0;
        if(cur->length >= 2) {
          cipher_suite_count = *(u_int16_t*)(cur->data);

          // puts("hi~!");
          // hexdump((char*)cur->data, cur->length);
          // getchar();
          
          if(cur->length >= 2 + 4 * cipher_suite_count + 2) {
            pairwise_suite_count = *(u_int16_t*)(cur->data + 2 + 4 * cipher_suite_count);
            if(cur->length >= 2 + 4 * cipher_suite_count + 2 + 4 * pairwise_suite_count + 2) {
              for(i = 0; i < pairwise_suite_count; ++i) {
                ap->cipher = std::max(ap->cipher, cur->data[2 + 4 * cipher_suite_count + 2 + 3 + 4 * i]);
              }
              auth_suite_count = *(u_int16_t*)(cur->data + 2 + 4 * cipher_suite_count + 2 + 4 * pairwise_suite_count);
              if(cur->length >= 2 + 4 * cipher_suite_count + 2 + 4 * auth_suite_count + 2 + 4 * pairwise_suite_count + 2) {
                for(i = 0; i < auth_suite_count; ++i) {
                  ap->auth = std::max(ap->auth, cur->data[2 + 4 * cipher_suite_count + 2 + 4 * pairwise_suite_count + 2 + 4 * i + 3]);
                }
                if(ap->auth == 4 || ap->auth == 9 || ap->auth == 12) {
                  ap->enc = 3;
                }
                else if (ap->cipher == 1 || ap->cipher == 5) {
                  ap->enc = 1;
                }
                if(ap->enc == 3 && (ap->auth == 8 || ap->auth == 18)) {
                  ap->enc = 4;
                }
                if(ap->enc == 1 && ap->auth == 2) {
                  ap->auth = 19;
                }
              }
            }
          }
        } 
      }
      else if (cur->number == 221) {
        if(cur->length >= 2 + 4 && !memcmp(cur->data, "\x00\x50\xF2\x01\x01\x00", 6)) {
          if(ap->enc == 0){
            ap->enc = 2;
            ap->cipher = 0;
            ap->auth = 0;
          }
          cipher_suite_count = *(u_int16_t*)(cur->data + 4);

          if(cur->length >= 4 + 2 + 4 * cipher_suite_count + 2) {
            pairwise_suite_count = *(u_int16_t*)(cur->data + 4 + 2 + 4 * cipher_suite_count);
            if(cur->length >= 4 + 2 + 4 * cipher_suite_count + 2 + 4 * pairwise_suite_count + 2) {
              for(i = 0; i < pairwise_suite_count; ++i) {
                ap->cipher = std::max(ap->cipher, cur->data[4 + 2 + 4 * cipher_suite_count + 2 + 3 + 4 * i]);
              }
              auth_suite_count = *(u_int16_t*)(cur->data + 4 + 2 + 4 * cipher_suite_count + 2 + 4 * pairwise_suite_count);
              if(cur->length >= 4 + 2 + 4 * cipher_suite_count + 2 + 4 * auth_suite_count + 2 + 4 * pairwise_suite_count + 2) {
                for(i = 0; i < auth_suite_count; ++i) {
                  ap->auth = std::max(ap->auth, cur->data[4 + 2 + 4 * cipher_suite_count + 2 + 4 * pairwise_suite_count + 2 + 4 * i + 3]);
                }
                if(ap->cipher == 4 || ap->cipher == 9 || ap->cipher == 12) {
                  ap->enc = 3;
                }
                else if (ap->cipher == 1 || ap->cipher == 4) {
                  ap->enc = 1;
                }
                if(ap->enc == 3 && (ap->cipher == 8 || ap->cipher == 18)) {
                  ap->enc = 4;
                }
                if(ap->enc == 1 && ap->cipher == 2) {
                  ap->cipher = 19;
                }
              }
            }
          }
        } 
      }
      cur = (tagged_parameter_t*)(cur->data + cur->length);
    }

    if (ap->ESSID == NULL) {
      ap->ESSID = new std::string();
    }

    ap->pwr = pwr;
    ap->beacons = 0;

    APs.push_back(ap);
    std::sort(APs.begin(), APs.end(), AP_pointer_cmp);
  }
  else {
    ap->pwr = pwr;
    ap->beacons += 1;
  }
}

void print_ap(int channel) {
  char mac_buf[18];
  size_t i;
  ap_t *ap;
  printf("\e[1;1H\e[2J");
  printf("\033[2d\033[0G");
  printf(" CH %2d\n\n", channel);
  printf(" BSSID              PWR  Beacons   ENC CIPHER  AUTH ESSID\n\n");
  
  for (i = 0; i < APs.size() && i < height - 7; ++i) {
    ap = APs[i];
    mac_to_str(ap->bssid, mac_buf);
    printf(" %s  %3hhd  %7u   %-4s %-5s  %-4s %s\n", mac_buf, ap->pwr, ap->beacons, ENC[ap->enc], CIPHER[ap->cipher], AUTH[ap->auth], ap->ESSID->c_str());
  }
}
