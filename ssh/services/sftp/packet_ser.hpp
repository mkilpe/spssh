#ifndef SP_SSH_SFTP_PACKET_SER_HEADER
#define SP_SSH_SFTP_PACKET_SER_HEADER

#include "packet_types.hpp"
#include "ssh/core/packet_ser.hpp"

namespace securepath::ssh::sftp {

/// this is serialisation for sftp packets, they differ from normal ssh packets by having first the packet length
template<std::uint8_t PacketType, typename... TypeTags>
class sftp_packet_ser;

/// returns the packet type if there is enough data for the whole packet, zero otherwise
sftp_packet_type decode_sftp_type(const_span, std::uint32_t& length);

}

#endif