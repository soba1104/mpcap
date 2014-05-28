#ifndef SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_SERVER_H_
#define SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_SERVER_H_

#include <mpcap/common.h>
#include <mpcap/stream/event/observer.h>
#include <mpcap/stream/event/subject/iface.h>

namespace mpcap {

namespace stream {

namespace event {

namespace subject {

template <typename ADDRESS>
class server : public iface<ADDRESS> {
  public:
    server(const ADDRESS &addr)
         : m_addr(addr), m_observer(NULL) {}
    ~server(void) {}

    void attach(observer::iface<ADDRESS> *o) {
      m_observer = o;
    }

    void detach(void) {
      m_observer = NULL;
    }

    void notify(const ADDRESS &src,
                const ADDRESS &dst,
                const void *data,
                const struct ::timeval &time) {
      if (!m_observer) {
        return;
      }
      if (src == m_addr) {
        m_observer->notify(event::type::send, src, dst, data, time);
      } else if (dst == m_addr) {
        m_observer->notify(event::type::recv, src, dst, data, time);
      }
    }

  private:
    const ADDRESS m_addr;
    observer::iface<ADDRESS> *m_observer;
};

} // namespace subject

} // namespace event

} // namespace stream

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_SERVER_H_
