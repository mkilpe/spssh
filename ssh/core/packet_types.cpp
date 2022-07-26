
#include "packet_types.hpp"

#include <ostream>

namespace securepath::ssh {

bool is_kex_packet(ssh_packet_type t) {
	return t >= 20 && t <= 49;
}

std::ostream& operator<<(std::ostream& out, ssh_packet_type t) {
	//t: implement string presentation for easy reading?
	return out << static_cast<std::uint32_t>(t);
}

}

