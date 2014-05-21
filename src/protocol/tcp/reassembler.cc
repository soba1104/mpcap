#include <mpcap/protocol/tcp/reassembler.h>

#include <map>
#include <string.h>

namespace mpcap {

namespace protocol {

class tcp::reassembler::impl {
  public:
    impl(void) : m_init(false), m_taken(NULL) {}
    ~impl(void);

    bool pass(const packet &p);
    void put(const packet &p);
    const packet *take(void);

  private:
    bool m_init;
    uint32_t m_seq;
    const packet *m_taken;
    std::map<uint32_t, packet*> m_packets;
};

tcp::reassembler::impl::~impl(void) {
  for (auto it = m_packets.begin(); it != m_packets.end(); it++) {
    packet *p = (*it).second;
    delete[] static_cast<const uint8_t*>(p->ptr());
    delete p;
  }
}

bool tcp::reassembler::impl::pass(const packet &p) {
  uint32_t seq = ntohl(p.seqnum());
  if (!m_init) {
    m_seq = seq;
    m_init = true;
  }
  if (m_seq == seq) {
    if (p.syn()) { ++m_seq; }
    m_seq += p.datasize();
    return true;
  } else {
    return false;
  }
}

void tcp::reassembler::impl::put(const packet &p) {
  if (!p.syn() && !p.datasize()) {
    return;
  }
  uint32_t seq = ntohl(p.seqnum());
  if (m_packets.find(seq) == m_packets.end()) {
    uint8_t *buf = (new uint8_t[p.size()]);
    memcpy(buf, p.ptr(), p.size());
    packet *clone = new packet;
    clone->apply(buf, p.size()); // TODO check return value
    m_packets[seq] = clone;
  }
  if (!m_init) {
    m_seq = seq;
    m_init = true;
  }
}

const tcp::packet *tcp::reassembler::impl::take(void) {
  if (!m_init || m_packets.find(m_seq) == m_packets.end()) {
    return NULL;
  }

  if (m_taken) {
    uint32_t taken_seq = ntohl(m_taken->seqnum());
    MPCAP_ASSERT(m_packets.find(taken_seq) != m_packets.end());
    delete[] static_cast<const uint8_t*>(m_taken->ptr());
    delete m_taken;
    m_packets.erase(taken_seq);
    m_taken = NULL;
  }

  const packet *p = m_packets[m_seq];
  if (p->syn()) { ++m_seq; }
  m_seq += p->datasize();
  m_taken = p;

  return p;
}

tcp::reassembler::reassembler(void)
                            : m_impl(new tcp::reassembler::impl()) {
}

tcp::reassembler::~reassembler(void) {
  delete m_impl;
}

bool tcp::reassembler::pass(const tcp::packet &p) {
  return m_impl->pass(p);
}

void tcp::reassembler::put(const tcp::packet &p) {
  m_impl->put(p);
}

const tcp::packet *tcp::reassembler::take(void) {
  return m_impl->take();
}

} // namespace protocol

} // namespace mpcap
