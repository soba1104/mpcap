#ifndef SRC_INCLUDE_MPCAP_PACKET_ETHERNET_H_
#define SRC_INCLUDE_MPCAP_PACKET_ETHERNET_H_

#include <mpcap/common.h>

namespace mpcap {

namespace protocol {

struct ethernet {

class address;
class packet;

};

} // namespace protocol

} // namespace mpcap

#include <mpcap/protocol/ethernet/address.h>
#include <mpcap/protocol/ethernet/packet.h>

#endif // SRC_INCLUDE_MPCAP_PACKET_ETHERNET_H_
