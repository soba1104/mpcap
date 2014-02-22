#ifndef SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_INTERFACE_H_
#define SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_INTERFACE_H_

#include <mpcap/common.h>
#include <mpcap/stream/event/observer.h>

namespace mpcap {

namespace stream {

namespace event {

namespace subject {

template <typename ADDRESS>
class interface {
  public:
    virtual ~interface(void) {}
    virtual void attach(observer::interface *o) = 0;
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

#endif // SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_INTERFACE_H_
