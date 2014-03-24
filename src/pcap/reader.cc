#include <sstream>
#include <pcap.h>

#include <mpcap/pcap/reader.h>

namespace mpcap {

namespace pcap {

class reader::impl {
  public:
    impl(const std::string &interface,
         const std::string &filter)
       : m_interface(interface),
         m_filter(filter),
         m_pcap(NULL) {}
    ~impl(void) { close(); }

    void open(void);
    void close(void);
    int32_t read(const void **res_data, struct ::timeval *res_time);

  private:
    const std::string m_interface;
    const std::string m_filter;
    pcap_t *m_pcap;
};

void reader::impl::open(void) {
  if (m_pcap) {
    return;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs;
  if (pcap_findalldevs(&devs, errbuf) == -1) {
    std::ostringstream os;
    os << "Failed to find devices. " << errbuf;
    throw reader::exception(os.str());
  }
  if (!devs) {
    std::ostringstream os;
    os << "No defice found.";
    throw reader::exception(os.str());
  }

  pcap_if_t *target_interface = NULL;
  for (pcap_if_t *device = devs; device; device = device->next) {
    if (device->name == m_interface) {
      target_interface = device;
    }
  }
  if (target_interface == NULL) {
    std::ostringstream os;
    os << "Failed to find device(" << m_interface << ").";
    throw reader::exception(os.str());
  }

  pcap_t *pcap = pcap_open_live(target_interface->name,
                                65536, // capture whole packet
                                true, // use promiscuous mode
                                0, // FIXME timeout msec
                                errbuf);
  if (!pcap) {
    std::ostringstream os;
    os << "Failed open interface(" << target_interface->name << "). " << errbuf;
    throw reader::exception(os.str());
  }

  bpf_u_int32 net, mask;
  if (pcap_lookupnet(target_interface->name, &net, &mask, errbuf) == -1) {
    std::ostringstream os;
    os << "Failed to lookup net. " << errbuf;
    pcap_close(pcap);
    throw reader::exception(os.str());
  }

  struct ::bpf_program fp;
  if (pcap_compile(pcap, &fp, m_filter.c_str(), true, mask) == -1) {
    std::ostringstream os;
    os << "Failed to compile filter(" << m_filter << "). " << errbuf;
    pcap_close(pcap);
    throw reader::exception(os.str());
  }

  if (pcap_setfilter(pcap, &fp) == -1) {
    std::ostringstream os;
    os << "Failed to set filter(" << m_filter << ").";
    pcap_close(pcap);
    throw reader::exception(os.str());
  }

  m_pcap = pcap;
}

void reader::impl::close(void) {
  if (m_pcap) {
    pcap_close(m_pcap);
    m_pcap = NULL;
  }
}

int32_t reader::impl::read(const void **res_data, struct ::timeval *res_time) {
  if (!m_pcap) {
    throw reader::exception("pcap::reader is not opened.");
  }
  
  struct pcap_pkthdr *hdr;
  const uint8_t *data;
  int result = pcap_next_ex(m_pcap, &hdr, &data);
  if (result != 1) {
    if (result == -1) {
      pcap_perror(m_pcap, const_cast<char*>("pcap_perror: ")); // FIXME
    }
    // TODO error handling
    return result;
  }
  *res_time = hdr->ts;
  *res_data = data;

  return hdr->len;
}

reader::reader(const std::string &interface,
               const std::string &filter)
             : m_impl(new reader::impl(interface, filter)) {}

reader::~reader(void) {
  delete m_impl;
}

void reader::open(void) {
  m_impl->open();
}

void reader::close(void) {
  m_impl->close();
}

int32_t reader::read(const void **res_data, struct ::timeval *res_time) {
  return m_impl->read(res_data, res_time);
}

} // namespace pcap

} // namespace mpcap
