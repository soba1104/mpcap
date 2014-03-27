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
    inline virtual int32_t size(void) const final override { return m_size; }
    inline virtual const void *ptr(void) const final override { return m_ihdr; }
    inline virtual int32_t datasize(void) const final override { return m_datasize; }
    inline virtual const void *dataptr(void) const final override { return m_dataptr; }

    inline uint32_t srcip(void) const { return m_ihdr->saddr; }
    inline uint32_t dstip(void) const { return m_ihdr->daddr; }

    inline address src(void) const { return address(srcip()); }
    inline address dst(void) const { return address(dstip()); }

    inline bool contain(const protocol::tcp &p, const void *data, int32_t size) {
      const struct iphdr *ihdr
        = static_cast<const struct iphdr*>(data);
      return ihdr->protocol == IPPROTO_TCP;
    }

    inline virtual bool contain(const protocol::interface &p, const void *data, int32_t size) final override {
      return false;
    }

    inline virtual bool apply(const void *data, int32_t size) final override {
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

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_IPV4_PACKET_H_
