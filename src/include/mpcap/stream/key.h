#ifndef SRC_INCLUDE_MPCAP_STREAM_KEY_H_
#define SRC_INCLUDE_MPCAP_STREAM_KEY_H_

#include <mpcap/common.h>

namespace mpcap {

namespace stream {

template <typename ADDRESS>
class key {
  public:
    struct hasher {
      size_t operator() (const key &k) const {
        return k.hash();
      }
    };

    key(const ADDRESS &src,
        const ADDRESS &dst)
      : m_src(src),
        m_dst(dst),
        m_hash((m_src.hash() << 1) ^ m_dst.hash()) {}
    ~key(void) {}

    bool operator==(const key &rhs) const {
      return m_src == rhs.m_src && m_dst == rhs.m_dst;
    }

    size_t hash(void) const {
      return m_hash;
    }

  private:
    const ADDRESS m_src, m_dst;
    const size_t m_hash;
};

} // namespace stream

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_STREAM_KEY_H_
