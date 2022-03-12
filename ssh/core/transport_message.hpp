#ifndef SP_SHH_TRANSPORT_MESSAGE_HEADER
#define SP_SHH_TRANSPORT_MESSAGE_HEADER

#include "ssh_binary_format.hpp"

namespace securepath::ssh {

std::size_t const uint32_size = 4;

/// string lenght + content
inline std::size_t string_size(std::size_t size) { return 4 + size; }

class transport_message : public ssh_bf_writer {
public:
	transport_message(out_buffer& out, ssh_packet_type type, std::size_t size)
	: ssh_bf_writer(out.get(1+size)) // type + size
	, out_(out)
	{
		add_uint8(type);
	}

	void done() {
		if(used_size()) {
			out_.commit(used_size());
		}
	}

private:
	out_buffer& out_;
};

}

#endif
