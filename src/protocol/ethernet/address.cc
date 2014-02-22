#include <mpcap/protocol/ethernet.h>

#include <stdio.h>

namespace mpcap {

namespace protocol {

namespace {

uint64_t parse(const char *str) {
  unsigned int a0, a1, a2, a3, a4, a5;
  sscanf(str,
         "%x:%x:%x:%x:%x:%x",
         &a0, &a1, &a2, &a3, &a4, &a5);
  return static_cast<uint64_t>(a0) << 0x28UL
       | static_cast<uint64_t>(a1) << 0x20UL
       | static_cast<uint64_t>(a2) << 0x18UL
       | static_cast<uint64_t>(a3) << 0x10UL
       | static_cast<uint64_t>(a4) << 0x08UL
       | static_cast<uint64_t>(a5) << 0x00UL;
}

} // namespace

ethernet::address::address(const char *str)
                         : base::address<uint64_t>(parse(str)) {}

ethernet::address::address(const std::string &str)
                         : base::address<uint64_t>(parse(str.c_str())) {}

} // protocol

} // mpcap
