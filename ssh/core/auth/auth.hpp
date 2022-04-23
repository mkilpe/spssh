#ifndef SP_SHH_AUTH_HEADER
#define SP_SHH_AUTH_HEADER

#include <string_view>

namespace securepath::ssh {

// supported authentication types [RFC 4252] [RFC 4256]
enum class auth_type {
	none         = 0,
	public_key   = 1,
	password     = 2,
	hostbased    = 4,
	interactive  = 8,
	end_of_list  = 16
};

using auth_bits = std::uint16_t;

auth_bits operator|(auth_type l, auth_type r);
auth_bits operator&(auth_bits l, auth_type r);

std::string_view to_string(auth_type);

}

#endif