#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_TCP_PACKET_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_TCP_PACKET_H_

#include <mpcap/common.h>
#include <mpcap/protocol/interface.h>
#include <mpcap/protocol/tcp.h>
#include <mpcap/protocol/tcp/address.h>

#include <netinet/tcp.h>
#include <string>

namespace mpcap {

namespace protocol {

class tcp::packet : public interface::packet {
  public:
    packet(void) {}
    ~packet(void) {}

    template<typename NEXT> bool apply(const void *data, int32_t size);
    inline virtual int32_t size(void) const final override { return m_size; }
    inline virtual const void *ptr(void) const final override { return m_thdr; }
    inline virtual int32_t datasize(void) const final override { return m_datasize; }
    inline virtual const void *dataptr(void) const final override { return m_dataptr; }

    inline uint16_t srcport(void) const { return m_thdr->source; }
    inline uint16_t dstport(void) const { return m_thdr->dest; }
    inline uint32_t seqnum(void) const { return m_thdr->seq; }
    inline uint32_t acknum(void) const { return m_thdr->ack_seq; }
    inline bool fin(void) const { return m_thdr->fin == 1; }
    inline bool syn(void) const { return m_thdr->syn == 1; }
    inline bool rst(void) const { return m_thdr->rst == 1; }
    inline bool psh(void) const { return m_thdr->psh == 1; }
    inline bool ack(void) const { return m_thdr->ack == 1; }
    inline bool urg(void) const { return m_thdr->urg == 1; }
    inline uint16_t window(void) const { return m_thdr->window; }
    inline uint16_t checksum(void) const { return m_thdr->check; }
    inline uint16_t urgptr(void) const { return m_thdr->urg_ptr; }

    inline address src(void) const { return address(srcport()); }
    inline address dst(void) const { return address(dstport()); }

    inline virtual bool contain(const protocol::interface &p, const void *data, int32_t size) final override {
      return false;
    }

    inline virtual bool apply(const void *data, int32_t size) final override {
      m_thdr = static_cast<const struct tcphdr*>(data);
      m_size = size;
      const uint8_t *__data = static_cast<const uint8_t*>(data);
      uint16_t hdrsize = m_thdr->doff * sizeof(uint32_t);
      m_dataptr = static_cast<const void*>(__data + hdrsize);
      m_datasize = m_size - hdrsize;
      return m_datasize >= 0;
    }

    std::string inspect(void) const;

  private:
    const struct tcphdr *m_thdr;
    const void *m_dataptr;
    int32_t m_size;
    int32_t m_datasize;
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_TCP_PACKET_H_
