#ifndef SRC_INCLUDE_MPCAP_PROTOCOL_IFACE_H_
#define SRC_INCLUDE_MPCAP_PROTOCOL_IFACE_H_

#include <mpcap/common.h>

namespace mpcap {

namespace protocol {

struct iface {
  class packet {
    public:
      virtual bool contain(const protocol::iface &p, const void *data, int32_t size) = 0;
      virtual bool apply(const void *data, int32_t size) = 0;
      virtual int32_t size(void) const = 0;
      virtual const void *ptr(void) const = 0;
      virtual int32_t datasize(void) const = 0;
      virtual const void *dataptr(void) const = 0;
  };
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PROTOCOL_IFACE_H_
