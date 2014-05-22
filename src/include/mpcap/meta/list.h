#ifndef SRC_INCLUDE_MPCAP_META_LIST_H_
#define SRC_INCLUDE_MPCAP_META_LIST_H_

#include <mpcap/common.h>

#include <functional>
#include <type_traits>

namespace mpcap {

namespace meta {

template<typename... TYPES> class list;

template<typename CAR, typename CDR>
class list<CAR, CDR> {
  public:
    struct hasher {
      size_t operator() (const list<CAR, CDR> &ah) const {
        return ah.hash();
      }
    };

    template <int I, typename T = void> struct index {
      typedef typename CDR::template index<I - 1>::type type;
    };

    template <int I> struct index<I, typename std::enable_if<I == 0>::type> {
      typedef CAR type;
    };

    explicit list<CAR, CDR>(CAR addr, const CDR &rest)
                          : m_car(addr), m_cdr(rest) {}

    template <typename... ARGS>
    list<CAR, CDR>(CAR car, ARGS... args)
                 : m_car(car), m_cdr(args...) {}

    list<CAR, CDR>(const list<CAR, CDR> &orig)
                 : m_car(orig.m_car), m_cdr(orig.m_cdr) {}

    list<CAR, CDR> &operator=(const list<CAR, CDR> &orig) {
      m_car = orig.m_car;
      m_cdr = orig.m_cdr;
    }

    bool operator==(const list<CAR, CDR> &rhs) const {
      return m_car == rhs.m_car && m_cdr == rhs.m_cdr;
    }

    template <int I>
    const typename index<I>::type &at(typename std::enable_if<I != 0>::type* = 0) const {
      return m_cdr.at<I - 1>();
    }

    template <int I>
    const CAR &at(typename std::enable_if<I == 0>::type* = 0) const {
      return m_car;
    }

    template <int I>
    const auto &slice(typename std::enable_if<I != 0>::type* = 0) const {
      return m_cdr.slice<I-1>();
    }

    template <int I>
    const typename meta::list<CAR, CDR> &slice(typename std::enable_if<I == 0>::type* = 0) const {
      return *this;
    }

    static constexpr int size(void) { return 1 + CDR::size(); }

    size_t hash(void) const {
      return m_car.hash() ^ m_cdr.hash();
    }

  private:
    CAR m_car;
    CDR m_cdr;
};

template<>
class list<> {
  public:
    struct hasher {
      size_t operator() (const list<> &ah) const {
        return ah.hash();
      }
    };

    list(void) {}

    list<> &operator=(const list<> &orig) {}

    template <int I> struct index {
      typedef void type;
    };

    template <int I> void at(void) const {}

    template <int I>
    void slice(typename std::enable_if<I != 0>::type* = 0) const {}

    template <int I>
    const typename meta::list<> &slice(typename std::enable_if<I == 0>::type* = 0) const {
      return *this;
    }

    static constexpr int size(void) { return 0; }

    bool operator==(const list<> &rhs) const {
      return true;
    }

    size_t hash(void) const {
      return 0;
    }
};

} // namespace meta

} // namespace mpcap

#endif // SRC_INCLUDE_MPCAP_META_LIST_H_
