#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_BASE_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_BASE_H_

#include <mpcap/common.h>

#include <functional>

namespace mpcap {

namespace protocol {

struct base {
  template <typename T> class address {
    public:
      address<T>(const T &val) : m_value(val) {}
      template <typename U> bool operator==(const U &v) const { return false; }
      size_t hash(void) const { std::hash<T>()(m_value); }
      T value(void) const { return m_value; }

    private:
      T m_value;
  };
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_BASE_H_
