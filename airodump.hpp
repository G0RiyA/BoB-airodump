#include <cstdint>
#include <string>
#include <map>
#include <vector>

#define MAC2INT(x) (*(u_int64_t*)(x) & 0xFFFFFFFFFFFF)

typedef u_int8_t mac_t[6];

typedef enum class _tag_number : u_int8_t {
  SSID = 0,
           RATES,
           FF,
           DS,
           CF,
           TIM,
           IBSS,
           COUNTRY_CODE,
           HOPPING_PATTERN_PARAMTER,
           HOPPING_PATTERN_TABLE,
           REQUEST,
           CHALLENGE_TEXT = 16,
           POWER_CONSTRAINT,
           HT_CAPABILITIES = 45,
           HT_OPERATION = 61,
           RSNA = 48,
           EXTENDED_CAPABILITIES = 127,
           VHT_CAPABILITIES = 191,
           VHT_OPERATION,
           VENDOR_SPECIFIC_ELEMENT
} tag_number;

typedef struct __attribute__((__packed__)) RatioHeader {
  u_int8_t revision;
  u_int8_t pad;
  u_int16_t length;
  u_int64_t present_flags;
  u_int8_t flags;
  u_int8_t data_rate;
  u_int16_t frequency;
  u_int16_t channel_flags;
  int8_t signal;
  u_int8_t pad_;
  u_int16_t RX_flag;
  int8_t signal_;
  u_int8_t antenna;
} ratio_header_t;

typedef struct __attribute__((__packed__)) Frame {
  unsigned version:2, type:2, subtype:4, flags:8;
  u_int16_t duration;
  mac_t receiver;
} frame_t;

typedef struct __attribute__((__packed__)) Probe {
  mac_t trasmitter;
  mac_t bss_id;
  unsigned fragment:4, sequence: 12;
} probe_t;

typedef struct __attribute__((__packed__)) TaggedParameter {
  u_int8_t number;
  u_int8_t length;
  u_int8_t data[];
} tagged_parameter_t;

typedef struct __attribute__((__packed__)) Beacon {
  mac_t trasmitter;
  mac_t bss_id;
  unsigned fragment:4, sequence: 12;
  u_int8_t fixed_parameter[12];
  tagged_parameter_t tp[];
} beacon_t;

typedef struct AP {
  std::string *ESSID;
  mac_t bssid;
  int8_t pwr;
  u_int32_t beacons;
  u_int64_t data;
  u_int8_t ch;
  u_int8_t enc;
  u_int8_t cipher;
  u_int8_t auth;
} ap_t;

const char *ENC[] = {
  "OPN", "WEP", "WPA", "WPA2", "WPA3"
};

const char *CIPHER[] = {
  "", "WEP40", "TKIP", "WRAP", "CCMP", "WEP140"
};

const char *AUTH[] = {
  "", "MGT", "PSK", "", "", "", "CMAC", "", "SAE", "", "", "", "", "CMAC", "", "", "", "", "OWE", "SKA"
};

std::map<u_int64_t, ap_t*> AP_map;
std::vector<ap_t*> APs;

bool AP_pointer_cmp(ap_t *a, ap_t *b) { return a->pwr > b->pwr; }
void mac_to_str(u_int8_t*, char*);
void append_probe_request(probe_t*,int8_t,void*);
void append_beacon_frame(beacon_t*,int8_t,void*);
void print_ap(int);

void hexdump(char *buf, size_t len) {
  size_t i;

  for(i = 0; i < len; ++i) {
    if(i > 0 && i % 16 == 0) puts("");
    printf("%02hhx ", buf[i]);
  }
}


