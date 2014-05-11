#ifndef SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_CLIENT_H_
#define SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_CLIENT_H_

#include <mpcap/common.h>
#include <mpcap/stream/event/observer.h>
#include <mpcap/stream/event/subject/iface.h>

namespace mpcap {

namespace stream {

namespace event {

namespace subject {

template <typename ADDRESS>
class client : public iface<ADDRESS> {
  public:
    client(const ADDRESS &caddr, const ADDRESS &saddr)
         : m_caddr(caddr), m_saddr(saddr), m_observer(NULL) {}
    ~client(void) {}

    void attach(observer::iface *o) {
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
      if (src == m_caddr && dst == m_saddr) {
        m_observer->notify(event::type::send, data, time);
      } else if (dst == m_caddr && src == m_saddr) {
        m_observer->notify(event::type::recv, data, time);
      }
    }

  private:
    const ADDRESS m_caddr, m_saddr;
    observer::iface *m_observer;
};

} // namespace subject

} // namespace event

} // namespace stream

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_STREAM_EVENT_SUBJECT_CLIENT_H_
