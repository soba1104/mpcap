#include <sstream>
#include <pcap.h>
#ifdef WIN32
#include <Iphlpapi.h>
#include <regex>
#endif

#include <mpcap/pcap/reader.h>

namespace mpcap {

namespace pcap {

class reader::impl {
  public:
    impl(const std::wstring &iface,
         const std::string &filter)
       : m_iface(iface),
         m_filter(filter),
         m_pcap(NULL) {}
    ~impl(void) { close(); }

    void open(void);
    void close(void);
    int32_t read(const void **res_data, struct ::timeval *res_time);

  private:
    const std::wstring get_friendly_device_name(const char *name);

    const std::wstring m_iface;
    const std::string m_filter;
    pcap_t *m_pcap;
};

const std::wstring reader::impl::get_friendly_device_name(const char *name) {
#ifdef WIN32
  IP_ADAPTER_ADDRESSES addresses[64]; // FIXME
  ULONG bufsize = sizeof(addresses);
  ULONG result = GetAdaptersAddresses(
    AF_UNSPEC,
    GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    addresses,
    &bufsize
  );
  if (result != NO_ERROR) {
    throw reader::exception("Failed to get adapter addresses.");
  }

  std::regex re("\\\\Device\\\\NPF_");
  std::string target_name(std::move(std::regex_replace(name, re, "")));
  const WCHAR *friendly_name = NULL;
  for (auto addrptr = addresses; addrptr; addrptr = addrptr->Next) {
    if (addrptr->AdapterName == target_name) {
      friendly_name = addrptr->FriendlyName;
      break;
    }
  }
  if (!friendly_name) {
    std::ostringstream os;
    os << "Failed to get device friendly name of " << name << ".";
    throw reader::exception(os.str());
  }
  return std::wstring(friendly_name);
#else
  return name;
#endif
}

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
    throw reader::exception("No defice found.");
  }

  pcap_if_t *target_iface = NULL;
  for (pcap_if_t *device = devs; device; device = device->next) {
    if (get_friendly_device_name(device->name) == m_iface) {
      target_iface = device;
    }
  }
  if (target_iface == NULL) {
    throw reader::exception("Failed to find specified device.");
  }

  pcap_t *pcap = pcap_open_live(
    target_iface->name,
    65536, // capture whole packet
    true, // use promiscuous mode
    0, // FIXME timeout msec
    errbuf
  );
  if (!pcap) {
    std::ostringstream os;
    os << "Failed open iface(" << target_iface->name << "). " << errbuf;
    throw reader::exception(os.str());
  }

  bpf_u_int32 net, mask;
  if (pcap_lookupnet(target_iface->name, &net, &mask, errbuf) == -1) {
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

reader::reader(const std::wstring &iface,
               const std::string &filter)
             : m_impl(new reader::impl(iface, filter)) {}

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
