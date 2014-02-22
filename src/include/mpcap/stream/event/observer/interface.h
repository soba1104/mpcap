#ifndef SRC_INCLUDE_MPCAP_STREAM_EVENT_OBSERVER_INTERFACE_H_
#define SRC_INCLUDE_MPCAP_STREAM_EVENT_OBSERVER_INTERFACE_H_

#include <mpcap/common.h>

#include <sys/time.h>

namespace mpcap {

namespace stream {

namespace event {

namespace observer {

class interface {
  public:
    virtual ~interface(void) {}
    virtual void notify(event::type type, const void *data, const struct ::timeval &time) = 0;
};

} // namespace observer

} // namespace event

} // namespace stream

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_STREAM_EVENT_OBSERVER_INTERFACE_H_
