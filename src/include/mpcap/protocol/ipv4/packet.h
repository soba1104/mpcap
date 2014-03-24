#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_

#include <mpcap/common.h>
#include <mpcap/protocol/interface.h>
#include <mpcap/protocol/ipv4.h>
#include <mpcap/protocol/tcp.h>

#include <netinet/ip.h>

namespace mpcap {

namespace protocol {

class ipv4::packet : public interface::packet {
  public:
    packet(void) {}
    ~packet(void) {}

    template<typename NEXT> bool apply(const void *data, int32_t size);
    inline int32_t size(void) const { return m_size; }
    inline const void *ptr(void) const { return m_ihdr; }
    inline int32_t datasize(void) const { return m_datasize; }
    inline const void *dataptr(void) const { return m_dataptr; }

    inline uint32_t srcip(void) const { return m_ihdr->saddr; }
    inline uint32_t dstip(void) const { return m_ihdr->daddr; }

    inline address src(void) const { return address(srcip()); }
    inline address dst(void) const { return address(dstip()); }

    bool apply(const void *data, int32_t size) {
      m_ihdr = static_cast<const struct iphdr*>(data);
      m_size = size;
      m_dataptr = static_cast<const void*>(m_ihdr + 1);
      m_datasize = m_size - sizeof(struct iphdr);
      return m_datasize >= 0;
    }

  private:
    const struct iphdr *m_ihdr;
    const void *m_dataptr;
    int32_t m_size;
    int32_t m_datasize;
}; // class packet

template<>
inline bool ipv4::packet::apply<tcp>(const void *data, int32_t size) {
  const struct iphdr *ihdr
    = static_cast<const struct iphdr*>(data);
  if (ihdr->protocol != IPPROTO_TCP) {
    return false;
  }
  return apply(data, size);
}

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_
