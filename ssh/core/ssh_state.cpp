#include "ssh_state.hpp"

#include <ostream>

namespace securepath::ssh {

char const* const state_strings[] =
	{ "none"
	, "version_exchange"
	, "kex"
	, "transport"
	, "disconnected"
	};

std::string_view to_string(ssh_state s) {
	return state_strings[std::size_t(s)];
}

std::ostream& operator<<(std::ostream& out, ssh_state state) {
	return out << to_string(state);
}

}
