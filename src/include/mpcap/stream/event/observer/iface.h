#ifndef SRC_INCLUDE_MPCAP_STREAM_EVENT_OBSERVER_IFACE_H_
#define SRC_INCLUDE_MPCAP_STREAM_EVENT_OBSERVER_IFACE_H_

#include <mpcap/common.h>

#include <sys/time.h>

namespace mpcap {

namespace stream {

namespace event {

namespace observer {

template <typename ADDRESS>
class iface {
  public:
    virtual ~iface(void) {}
    virtual void notify(event::type type,
                        const ADDRESS &src,
                        const ADDRESS &dst,
                        const void *data,
                        const struct ::timeval &time) = 0;
};

} // namespace observer

} // namespace event

} // namespace stream

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_STREAM_EVENT_OBSERVER_IFACE_H_
