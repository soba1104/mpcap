#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_

#include <mpcap/common.h>
#include <mpcap/protocol/iface.h>
#include <mpcap/protocol/ipv4.h>
#include <mpcap/protocol/tcp.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/ip.h>
#endif

namespace mpcap {

namespace protocol {

class ipv4::packet : public iface::packet {
  struct header {
    uint8_t vh; // version and headersize
    uint8_t tos;
    uint16_t size;
    uint16_t id;
    uint16_t flg; // flags and fragment offset
    uint8_t ttl;
    uint8_t protocol;
    uint32_t srcip;
    uint32_t dstip;
  };

  public:
    packet(void) {}
    ~packet(void) {}

    template<typename NEXT> bool apply(const void *data, int32_t size);
    inline virtual int32_t size(void) const final override { return m_size; }
    inline virtual const void *ptr(void) const final override { return m_header; }
    inline virtual int32_t datasize(void) const final override { return m_datasize; }
    inline virtual const void *dataptr(void) const final override { return m_dataptr; }

    inline uint32_t srcip(void) const { return m_header->srcip; }
    inline uint32_t dstip(void) const { return m_header->dstip; }

    inline address src(void) const { return address(srcip()); }
    inline address dst(void) const { return address(dstip()); }

    inline bool contain(const protocol::tcp &p, const void *data, int32_t size) {
      const struct header *hdr
        = static_cast<const struct header*>(data);
      return hdr->protocol == IPPROTO_TCP;
    }

    inline virtual bool contain(const protocol::iface &p, const void *data, int32_t size) final override {
      return false;
    }

    inline virtual bool apply(const void *data, int32_t size) final override {
      m_header = static_cast<const struct header*>(data);
      m_size = size;
      const uint8_t *__data = static_cast<const uint8_t*>(data);
      int32_t hdrsize = (m_header->vh & 0x0f) * sizeof(uint32_t);
      m_dataptr = static_cast<const void*>(__data + hdrsize);
      m_datasize = m_size - hdrsize;
      return m_datasize >= 0;
    }

  private:
    const struct header *m_header;
    const void *m_dataptr;
    int32_t m_size;
    int32_t m_datasize;
}; // class packet

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_
