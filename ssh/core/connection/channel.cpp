
#include "channel.hpp"

namespace securepath::ssh {

channel::channel(transport_base& transport)
: transport_(transport)
{
}

bool channel::send_data(const_span s) {
	bool res = out_window_ >= s.size();
	if(res) {

	}
	return res;
}

bool channel::send_extended_data(const_span s) {

}

bool channel::send_eof() {

}

bool channel::send_close() {

}

bool channel::send_window_adjust(std::uint32_t n) {

}

}

