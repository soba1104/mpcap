#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_TCP_REASSEMBLER_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_TCP_REASSEMBLER_H_

#include <mpcap/common.h>
#include <mpcap/protocol/tcp.h>
#include <mpcap/protocol/tcp/packet.h>

namespace mpcap {

namespace protocol {

class tcp::reassembler {
  public:
    reassembler(void);
    ~reassembler(void);

    bool pass(const packet &tp);
    void put(const packet &tp);
    const packet *take(void);

  private:
    DISALLOW_COPY_AND_ASSIGN(reassembler);

    class impl;
    impl *m_impl;
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_TCP_REASSEMBLER_H_
