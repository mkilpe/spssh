#ifndef SP_SHH_STATE_HEADER
#define SP_SHH_STATE_HEADER

#include <iosfwd>
#include <string_view>

namespace securepath::ssh {

enum class ssh_state {
	none,
	version_exchange,
	kex,
	transport,
	disconnected,
};
std::string_view to_string(ssh_state);
std::ostream& operator<<(std::ostream&, ssh_state);

enum class handler_result {
	unknown,  //unknown packet type, cannot handle
	handled, //the packet was handled
	pending //handling the packet is still in progress
};

}

#endif
