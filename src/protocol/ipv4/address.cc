#include <mpcap/protocol/ipv4.h>

#include <arpa/inet.h>

namespace mpcap {

namespace protocol {

namespace {

uint32_t parse(const char *str) {
  struct in_addr a;
  inet_pton(AF_INET, str, &a);
  return a.s_addr;
}

} // namespace

ipv4::address::address(const char *str)
                     : base::address<uint32_t>(parse(str)) {}

ipv4::address::address(const std::string &str)
                     : base::address<uint32_t>(parse(str.c_str())) {}

} // protocol

} // mpcap
