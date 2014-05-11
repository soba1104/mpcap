#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_TCP_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_TCP_H_

#include <mpcap/common.h>
#include <mpcap/protocol/iface.h>

namespace mpcap {

namespace protocol {

struct tcp : public protocol::iface {
  class address;
  class packet;
  class reassembler;
};

} // namespace protocol

} // namespace mpcap

#include <mpcap/protocol/tcp/address.h>
#include <mpcap/protocol/tcp/packet.h>
#include <mpcap/protocol/tcp/reassembler.h>

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_TCP_H_
