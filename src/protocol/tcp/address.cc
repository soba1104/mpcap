#include <mpcap/protocol/tcp.h>

#include <arpa/inet.h>

namespace mpcap {

namespace protocol {

namespace {

uint16_t parse(const char *str) {
  return static_cast<uint16_t>(htons(atoi(str)));
}

} // namespace

tcp::address::address(const char *str)
                    : base::address<uint16_t>(parse(str)) {}

tcp::address::address(const std::string &str)
                    : base::address<uint16_t>(parse(str.c_str())) {}

} // protocol

} // mpcap
