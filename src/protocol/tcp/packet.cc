#include <mpcap/protocol/tcp/packet.h>

#include <sstream>
#include <arpa/inet.h>

namespace mpcap {

namespace protocol {

std::string tcp::packet::inspect(void) const {
  std::ostringstream os;

  os << "seqnum(" << ntohl(seqnum()) << ") "
     << "acknum(" << ntohl(acknum()) << ") "
     << std::endl;
  os << "fin(" << fin() << ") "
     << "syn(" << syn() << ") "
     << "rst(" << rst() << ") "
     << "psh(" << psh() << ") "
     << "ack(" << ack() << ") "
     << "urg(" << urg() << ") "
     << std::endl;
  os << "window(" << window() << ") "
     << "checksum(" << checksum() << ") "
     << "urgptr(" << urgptr() << ") "
     << "datasize(" << datasize() << ") ";

  return os.str();
}

} // protocol

} // mpcap
