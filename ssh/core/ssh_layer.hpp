#ifndef SP_SSH_LAYER_HEADER
#define SP_SSH_LAYER_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class out_buffer;

class ssh_layer {
public:
	virtual ~ssh_layer() = default;

	//virtual layer_op handle(std::uint32_t type, const_span, out_buffer&) = 0;
};

}

#endif
