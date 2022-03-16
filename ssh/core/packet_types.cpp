
#include "packet_types.hpp"

#include <ostream>

namespace securepath::ssh {

std::ostream& operator<<(std::ostream& out, ssh_packet_type t) {
	//t: implement string presentation for easy reading?
	return out << static_cast<std::uint32_t>(t);
}

}

