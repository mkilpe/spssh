#ifndef SP_SHH_PACKET_SER_HEADER
#define SP_SHH_PACKET_SER_HEADER

#include "packet_types.hpp"

#include <string_view>
#include <vector>

namespace securepath::ssh::ser {

// type tags for packet serialisation
struct boolean;
struct byte;
struct uint32;
struct uint64;
struct mpint;
struct string;
struct name_list;
using name_list_t = std::vector<std::string_view>;

template<std::size_t size>
struct bytes;

template<std::uint8_t PacketType, typename... TypeTags>
class ssh_packet_ser;

template<typename Packet, typename... Args>
bool serialise_to_vector(byte_vector& out, Args&&... args) {
	typename Packet::save packet(std::forward<Args>(args)...);
	auto old_size = out.size();
	out.resize(old_size + packet.size());
	return packet.write(span{&out[old_size], packet.size()});
}

}

#endif
