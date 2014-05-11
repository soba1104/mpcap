#ifndef SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_IFACE_H_
#define SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_IFACE_H_

#include <mpcap/common.h>
#include <mpcap/stream/event/observer.h>

namespace mpcap {

namespace stream {

namespace event {

namespace subject {

template <typename ADDRESS>
class iface {
  public:
    virtual ~iface(void) {}
    virtual void attach(observer::iface *o) = 0;
    virtual void detach(void) = 0;
    virtual void notify(const ADDRESS &src,
                        const ADDRESS &dst,
                        const void *data,
                        const struct ::timeval &time) = 0;
};

} // namespace subject

} // namespace event

} // namespace stream

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_IFACE_H_
