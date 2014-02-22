#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_ADDRESS_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_ADDRESS_H_

#include <mpcap/common.h>
#include <mpcap/protocol/base.h>
#include <mpcap/protocol/ipv4.h>

#include <string>

namespace mpcap {

namespace protocol {

class ipv4::address : public base::address<uint32_t> {
  public:
    address(const uint32_t &val) : base::address<uint32_t>(val) {}
    address(const char *str);
    address(const std::string &str);
    bool operator==(const address &a) const { return value() == a.value(); }
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_ADDRESS_H_
