#ifndef SP_SSH_SFTP_PACKET_SER_HEADER
#define SP_SSH_SFTP_PACKET_SER_HEADER

#include "ssh/core/packet_ser.hpp"

namespace securepath::ssh::sftp {

/// this is serialisation for sftp packets, they differ from normal ssh packets by having first the packet length
template<std::uint8_t PacketType, typename... TypeTags>
class sftp_packet_ser;

}

#endif