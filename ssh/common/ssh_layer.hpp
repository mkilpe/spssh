#ifndef SP_SSH_LAYER_HEADER
#define SP_SSH_LAYER_HEADER

#include "types.hpp"

namespace securepath::ssh {

class in_buffer;
class out_buffer;

enum class layer_op {
	none,
	want_more,
	rekeying,
	disconnected
};

class ssh_layer {
public:
	virtual ~ssh_layer() = default;

	virtual layer_op handle(std::uint32_t type, const_span, out_buffer&) = 0;
};

}

#endif
