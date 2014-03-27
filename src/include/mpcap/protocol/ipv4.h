#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_H_

#include <mpcap/common.h>
#include <mpcap/protocol/interface.h>

namespace mpcap {

namespace protocol {

struct ipv4 : public protocol::interface {
  class address;
  class packet;
}; // struct ipv4

} // namespace protocol

} // namespace mpcap

#include <mpcap/protocol/ipv4/address.h>
#include <mpcap/protocol/ipv4/packet.h>

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_H_
