#ifndef SRC_INCLUDE_MPCAP_PACKET_READER_H_
#define SRC_INCLUDE_MPCAP_PACKET_READER_H_

#include <string>
#include <stdexcept>
#include <sys/time.h>

#include <mpcap/common.h>

namespace mpcap {

namespace packet {

class reader {
  public:
    class exception;

    reader(const std::string &interface, const std::string &filter);
    ~reader(void);
    void open(void);
    void close(void);
    int32_t read(const void **res_data, struct ::timeval *res_time);

  private:
    DISALLOW_COPY_AND_ASSIGN(reader);
    class impl;
    impl *m_impl;
};

class reader::exception : public std::runtime_error {
  public:
    exception(const std::string &message)
            : std::runtime_error(message) {}
};

} // namespace packet

} // namespace mpcap

#endif  // SRC_INCLUDE_MPCAP_PACKET_READER_H_
