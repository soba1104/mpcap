#ifndef SRC_INCLUDE_MPCAP_PACKET_LAYER_H_
#define SRC_INCLUDE_MPCAP_PACKET_LAYER_H_

#include <mpcap/common.h>
#include <mpcap/meta.h>

#include <type_traits>

namespace mpcap {

namespace protocol {

template<typename... PROTOCOLS> class stack;

template <typename HEAD, typename NEXT, typename... REST>
class stack<HEAD, NEXT, REST...> {
  public:

    typedef meta::list<typename HEAD::address,
                       typename stack<NEXT, REST...>::address> address;

    template <int I, typename T = void> struct protocol {
      typedef typename stack<NEXT, REST...>::template protocol<I - 1>::type type;
    };

    template <int I> struct protocol<I, typename std::enable_if<I == 0>::type> {
      typedef HEAD type;
    };

    class packet {
      public:
        packet() {}
        ~packet() {}

        template <int I>
        const typename protocol<I>::type::packet &at(typename std::enable_if<I != 0>::type* = 0) const {
          return m_rest.at<I - 1>();
        }
        template <int I>
        const typename HEAD::packet &at(typename std::enable_if<I == 0>::type* = 0) const {
          return m_head;
        }

        address src(void) { return address(m_head.src(), m_rest.src()); }
        address dst(void) { return address(m_head.dst(), m_rest.dst()); }

        bool apply(const void *data, uint32_t size) {
          if (!m_head.template apply<NEXT>(data, size)) { return false; }
          return m_rest.apply(m_head.dataptr(), m_head.datasize());
        }

      private:
        DISALLOW_COPY_AND_ASSIGN(packet);

        typename HEAD::packet m_head;
        typename stack<NEXT, REST...>::packet m_rest;
    };

  private:
    stack<HEAD, NEXT, REST...>() {}
    ~stack<HEAD, NEXT, REST...>() {}
};

template <typename HEAD>
class stack<HEAD> {
  public:
    typedef meta::list<typename HEAD::address, meta::list<>> address;

    template <int I, typename T = void> struct protocol {
      typedef void type;
    };

    template <int I> struct protocol<I, typename std::enable_if<I == 0>::type> {
      typedef HEAD type;
    };

    class packet {
      public:
        packet() {}
        ~packet() {}

        template <int I>
        const typename HEAD::packet &at(typename std::enable_if<I == 0>::type* = 0) const {
          return m_head;
        }

        address src(void) { return address(m_head.src(), meta::list<>()); }
        address dst(void) { return address(m_head.dst(), meta::list<>()); }

        bool apply(const void *data, uint32_t size) {
          return m_head.template apply(data, size);
        }

      private:
        DISALLOW_COPY_AND_ASSIGN(packet);

        typename HEAD::packet m_head;
    };

  private:
    stack<HEAD>() {}
    ~stack<HEAD>() {}
};

} // namespace protocol

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_PACKET_LAYER_H_
