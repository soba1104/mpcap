#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_TCP_PACKET_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_TCP_PACKET_H_

#include <mpcap/common.h>
#include <mpcap/protocol/iface.h>
#include <mpcap/protocol/tcp.h>
#include <mpcap/protocol/tcp/address.h>

#include <string>

namespace mpcap {

namespace protocol {

class tcp::packet : public iface::packet {
  struct header {
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgptr;
  };

  public:
    packet(void) {}
    ~packet(void) {}

    template<typename NEXT> bool apply(const void *data, int32_t size);
    inline virtual int32_t size(void) const final override { return m_size; }
    inline virtual const void *ptr(void) const final override { return m_header; }
    inline virtual int32_t datasize(void) const final override { return m_datasize; }
    inline virtual const void *dataptr(void) const final override { return m_dataptr; }

    inline uint16_t srcport(void) const { return m_header->srcport; }
    inline uint16_t dstport(void) const { return m_header->dstport; }
    inline uint32_t seqnum(void) const { return m_header->seqnum; }
    inline uint32_t acknum(void) const { return m_header->acknum; }
    inline uint8_t offset(void) const { return (m_header->offset & 0xf0) >> 4; }
    inline bool fin(void) const { return m_header->flags & 0x01; }
    inline bool syn(void) const { return m_header->flags & 0x02; }
    inline bool rst(void) const { return m_header->flags & 0x04; }
    inline bool psh(void) const { return m_header->flags & 0x08; }
    inline bool ack(void) const { return m_header->flags & 0x10; }
    inline bool urg(void) const { return m_header->flags & 0x20; }
    inline uint16_t window(void) const { return m_header->window; }
    inline uint16_t checksum(void) const { return m_header->checksum; }
    inline uint16_t urgptr(void) const { return m_header->urgptr; }

    inline address src(void) const { return address(srcport()); }
    inline address dst(void) const { return address(dstport()); }

    inline virtual bool contain(const protocol::iface &p, const void *data, int32_t size) final override {
      return false;
    }

    inline virtual bool apply(const void *data, int32_t size) final override {
      m_header = static_cast<const struct header*>(data);
      m_size = size;
      const uint8_t *__data = static_cast<const uint8_t*>(data);
      int32_t hdrsize = offset() * sizeof(uint32_t);
      m_dataptr = static_cast<const void*>(__data + hdrsize);
      m_datasize = m_size - hdrsize;
      return m_datasize >= 0;
    }

    std::string inspect(void) const;

  private:
    const struct header *m_header;
    const void *m_dataptr;
    int32_t m_size;
    int32_t m_datasize;
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_TCP_PACKET_H_
