#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_ETHERNET_PACKET_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_ETHERNET_PACKET_H_

#include <mpcap/common.h>
#include <mpcap/protocol/iface.h>
#include <mpcap/protocol/ethernet.h>
#include <mpcap/protocol/ipv4.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/if_ether.h>
#endif

namespace mpcap {

namespace protocol {

class ethernet::packet : public iface::packet {
  struct header {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
  };

  public:
    packet(void) {}
    ~packet(void) {}

    template<typename NEXT> bool apply(const void *data, int32_t size);
    inline virtual int32_t size(void) const final override { return m_size; }
    inline virtual const void *ptr(void) const final override { return m_header; }
    inline virtual int32_t datasize(void) const final override { return m_datasize; }
    inline virtual const void *dataptr(void) const final override { return m_dataptr; }

    inline address src(void) const {
      return address(static_cast<uint64_t>(m_header->src[0]) << 0x28UL
                   | static_cast<uint64_t>(m_header->src[1]) << 0x20UL
                   | static_cast<uint64_t>(m_header->src[2]) << 0x18UL
                   | static_cast<uint64_t>(m_header->src[3]) << 0x10UL
                   | static_cast<uint64_t>(m_header->src[4]) << 0x08UL
                   | static_cast<uint64_t>(m_header->src[5]) << 0x00UL);
    }
    inline address dst(void) const {
      return address(static_cast<uint64_t>(m_header->dst[0]) << 0x28UL
                   | static_cast<uint64_t>(m_header->dst[1]) << 0x20UL
                   | static_cast<uint64_t>(m_header->dst[2]) << 0x18UL
                   | static_cast<uint64_t>(m_header->dst[3]) << 0x10UL
                   | static_cast<uint64_t>(m_header->dst[4]) << 0x08UL
                   | static_cast<uint64_t>(m_header->dst[5]) << 0x00UL);
    }

    inline bool contain(const protocol::ipv4 &p, const void *data, int32_t size) {
      const struct header *header
        = static_cast<const struct header*>(data);
      uint16_t type = ntohs(header->type);
      return type == ETH_P_IP;
    }

    inline virtual bool contain(const protocol::iface &p, const void *data, int32_t size) final override {
      return false;
    }

    inline virtual bool apply(const void *data, int32_t size) final override {
      m_header = static_cast<const struct header*>(data);
      m_size = size;
      m_dataptr = static_cast<const void*>(m_header + 1);
      m_datasize = m_size - sizeof(struct header);
      return m_datasize >= 0;
    }

  private:
    const struct header *m_header;
    const void *m_dataptr;
    int32_t m_size;
    int32_t m_datasize;
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_ETHERNET_PACKET_H_
