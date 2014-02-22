#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_ETHERNET_ADDRESS_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_ETHERNET_ADDRESS_H_

#include <mpcap/common.h>
#include <mpcap/protocol/base.h>
#include <mpcap/protocol/ethernet.h>

#include <string>

namespace mpcap {

namespace protocol {

class ethernet::address : public base::address<uint64_t> {
  public:
    address(const uint64_t &val) : base::address<uint64_t>(val) {}
    address(const char *str);
    address(const std::string &str);
    bool operator==(const address &a) const { return value() == a.value(); }
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_ETHERNET_ADDRESS_H_
