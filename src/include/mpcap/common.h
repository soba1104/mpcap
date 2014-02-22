#ifndef SRC_INCLUDE_MPCAP_COMMON_H_
#define SRC_INCLUDE_MPCAP_COMMON_H_

#include <cstddef>
#include <cstdint>

#ifdef MPCAP_DEBUG
#include <assert.h>
#define MPCAP_ASSERT(expr) assert((expr))
#else
#define MPCAP_ASSERT(expr)
#endif

#define DISALLOW_COPY(T) \
  T(const T&);

#define DISALLOW_ASSIGN(T) \
  void operator=(const T&);

#define DISALLOW_COPY_AND_ASSIGN(T) \
  DISALLOW_COPY(T); \
  DISALLOW_ASSIGN(T);

#endif  // SRC_INCLUDE_MPCAP_COMMON_H_
