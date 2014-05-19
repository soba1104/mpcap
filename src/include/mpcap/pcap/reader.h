#ifndef SRC_INCLUDE_MPCAP_PCAP_READER_H_
#define SRC_INCLUDE_MPCAP_PCAP_READER_H_

#include <string>
#include <stdexcept>

#include <mpcap/common.h>

namespace mpcap {

namespace pcap {

class MPCAP_EXPORT reader {
  public:
    class exception;

    reader(const std::string &iface, const std::string &filter);
    reader(const std::wstring &iface, const std::string &filter);
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

} // namespace pcap

} // namespace mpcap

#endif  // SRC_INCLUDE_MPCAP_PCAP_READER_H_
